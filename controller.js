const {User,RefreshToken}=require('./models');
const crypto=require('crypto');
const jwt=require('jsonwebtoken');
const mongoose=require('mongoose');

const cookieOptions={
    httpOnly : true,
    maxAge : 7*24*3600*1000
};

User.on('index', function(err) {
    if (err) {
        console.error('User index error: %s', err);
    } else {
        console.info('User indexing complete');
    }
});

RefreshToken.on('index',function(err){
    if (err) {
        console.error('User index error: %s', err);
    } else {
        console.info('User indexing complete');
    }
});

function asyncHandler(fn){
    return async function (req,res,next){
        try{
            return await fn(req,res,next);
        }catch(err){
            console.log(err);
            if(err.code===11000) return next(createError(409,'Write conflict detected'));
            return next(err);
        }
    }
}

function createError(statusCode,message){
    const error=new Error(message ?? 'Something went wrong. Please try again.');
    error.statusCode=statusCode ?? 500;
    return error;   
}

const generateRefreshToken=()=>crypto.randomBytes(32).toString('hex');
const hash=string=>crypto.createHash('sha256').update(string).digest('hex');

const incompleteCredentialsError=createError(400,'Incomplete credentials');
const resourceNotFoundError=createError(404,'Requested resource group could not be found.');
const sessionExpiredError=createError(401,'Invalid or expired session. Log in again to continue.')

const validEmail=email=>/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
const validUsername=username=>/^[a-zA-Z0-9_]{3,16}$/.test(username);

const authMiddleware=asyncHandler(async (req,res,next)=>{
    const authHeader=req.headers.authorization;
    const accessToken=authHeader?.split(' ')[1];
    if(!authHeader || !accessToken)
        throw incompleteCredentialsError;
    try{
        req.user=jwt.verify(accessToken,process.env.JWT_ACCESS_SECRET);
    }catch(err){
        return next(sessionExpiredError);
    }
    next();
});

const signupUser=asyncHandler(async (req,res)=>{
    const {name,username,email,password}=req.body;
    if(!name || !username || !email || !password) throw incompleteCredentialsError;
    const checkUser=await User.findOne({$or : [{username},{email}]});
    if(checkUser) throw createError(409,'Username or email already exists');
    const user=new User({name,username,email,password});
    await user.save();
    return res.status(201).json({
        success : true,
        message : 'Successfully created new user. Log in to continue.'
    });
});

const loginUser=asyncHandler(async (req,res)=>{
    const {identifier,password,deviceId}=req.body;
    if(!identifier || !password || !deviceId) throw incompleteCredentialsError;
    var user=null,authenticated=false;
    if(validEmail(identifier)) user=await User.findOne({email : identifier});
    else if(validUsername(identifier)) user=await User.findOne({username : identifier});
    if(user) authenticated=await user.matchPassword(password);
    if(!authenticated) throw createError(401,'Invalid username/email or password');
    const session=await mongoose.startSession();
    try{
        var refreshToken;
        await session.withTransaction(async function (){
            const check=await RefreshToken.findOneAndUpdate({deviceId,revoked : false},{$set : {revoked : true}},{session,returnDocument : 'before'});
            if(check) await User.updateOne({_id : check.userId},{$inc : {activeSessions : -1}},{session});
            const result=await User.updateOne({_id : user._id, activeSessions : {$lt : 3}}, {$inc : {activeSessions : 1}},{session});
            if(result.modifiedCount===0) throw createError(409,'Device limit: 3 devices');
            refreshToken=generateRefreshToken();
            const tokenHash=hash(refreshToken);
            const refresh_token=new RefreshToken({
                tokenHash,
                userId : user._id,
                expiresAt : Date.now()+7*24*3600*1000,
                absoluteExpiresAt : Date.now()+30*24*3600*1000,
                deviceId
            });
            await refresh_token.save({session});
        });
        const accessToken=jwt.sign({id : user._id},process.env.JWT_ACCESS_SECRET,{expiresIn : 300});
        res.cookie('refreshToken',refreshToken,cookieOptions);
        return res.status(200).json({
            success : true,
            message : 'Successfully logged user in',
            accessToken
        });
    }catch(err){
        if(err.code===11000) throw createError(409,'Write conflict detected.');
        throw err;
    }finally{
        await session.endSession();
    }
});

const refreshSession=asyncHandler(async (req,res)=>{
    const {refreshToken}=req.cookies;
    if(!refreshToken) throw incompleteCredentialsError;
    const tokenHash=hash(refreshToken);
    const session=await mongoose.startSession();
    try{
        var result=null,newRefreshToken=null;
        await session.withTransaction(async function (){
            result=await RefreshToken.findOneAndUpdate({tokenHash, revoked : false},{revoked : true},{returnDocument : 'before', session});
            if(!result){
                const revoked=await RefreshToken.findOne({tokenHash,revoked : true});
                if(revoked){
                    await RefreshToken.updateMany({userId : revoked.userId},{revoked : true},{session});
                    await User.updateOne({_id : revoked.userId},{activeSessions : 0},{session});
                    throw createError(403,'Token reuses detected. Logging out all user sessions');
                }
                throw sessionExpiredError;
            }
            if(Date.now()>result.absoluteExpiresAt) throw sessionExpiredError;
            newRefreshToken=generateRefreshToken();
            const newTokenHash=hash(newRefreshToken);
            const refreshToken=new RefreshToken({
                tokenHash : newTokenHash,
                userId : result.userId,
                expiresAt : Date.now()+7*24*3600*1000,
                absoluteExpiresAt : result.absoluteExpiresAt,
                deviceId : result.deviceId
            });
            await refreshToken.save({session});
        });
        const accessToken=jwt.sign({id : result.userId},process.env.JWT_ACCESS_SECRET,{expiresIn : 300});
        res.cookie('refreshToken',newRefreshToken,cookieOptions);
        return res.status(200).json({
            success : true,
            message : 'Successfully refresh user session',
            accessToken
        });
    }catch(err){
        if(err.code===11000) throw createError(409,'Device session already exists.');
        throw err;
    }finally{
        await session.endSession();
    }
});

const logoutUser=asyncHandler(async (req,res)=>{
    const {refreshToken}=req.cookies;
    if(refreshToken){
        const hashedToken=hash(refreshToken);
        const session=await mongoose.startSession();
        try{
            await session.withTransaction(async function (){
                const result=await RefreshToken.findOneAndUpdate({tokenHash : hashedToken, revoked : false},{revoked : true},{returnDocument : 'before',session});
                if(result)
                    await User.updateOne({_id : result.userId},{$inc : {activeSessions : -1}},{session});
            });
        }catch(err){
            throw err;
        }finally{
            await session.endSession();
        }
    }
    res.clearCookie('refreshToken',{httpOnly : true});
    return res.status(200).json({
        success : true,
        message : 'Successfully logged user out.'
    });
});

const getUserInformation=asyncHandler(async (req,res)=>{
    const {user}=req;
    const fetchUser=await User.findOne({_id : user.id});
    if(!fetchUser)
        throw resourceNotFoundError;
    const userInfo={
        name : fetchUser.name,
        username : fetchUser.username,
        email : fetchUser.email
    };
    return res.status(200).json({
        success : true,
        message : 'Successfully fetched user information.',
        data : userInfo
    });
});

module.exports={signupUser,loginUser,refreshSession,logoutUser,getUserInformation,authMiddleware};
