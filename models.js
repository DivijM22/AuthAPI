const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const { refreshSession } = require('./controller');

const {Schema}=mongoose;

const userSchema=new Schema({
    name : {
        type : String,
        required : true
    },
    username : {
        type : String,
        unique : true,
        required : true,
        minLength : 4,
        maxLength : 25,
    },
    email : {
        type : String,
        required : true,
        unique : true,
        match : [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,'Enter valid email address'],
        lowercase : true
    },
    password : {
        type : String,
        required : true
    },
    role : {
        type : String,
        enum : ['user','moderator','admin'],
        default : 'user'
    },
    activeSessions : {
        type : Number,
        default : 0,
        min : 0,
        max : 3
    }
},{timestamps : true});

userSchema.pre('save',async function (){
    if(!this.isModified('password')) return;
    const salt=await bcrypt.genSalt(10);
    this.password=await bcrypt.hash(this.password,salt);
});

userSchema.methods.matchPassword=async function(password){
    return bcrypt.compare(password,this.password);
}

const refreshTokenSchema=new Schema({
    tokenHash : {
        type : String,
        required : true,
        unique : true
    },
    userId : {
        type : Schema.Types.ObjectId,
        required : true,
        ref : 'User'
    },
    revoked : {
        type : Boolean,
        default : false
    },
    expiresAt : {
        type : Date
    },
    absoluteExpiresAt : {
        type : Date,
        required : true
    },
    deviceId : {
        type : String,
        required : true,
    }
},{timestamps : true});

refreshTokenSchema.index({userId : 1, deviceId : 1},{unique : true, partialFilterExpression : {revoked : false}});
refreshTokenSchema.index({absoluteExpiresAt : 1},{expireAfterSeconds : 0});

module.exports={User : mongoose.model('User',userSchema),RefreshToken : mongoose.model('RefreshToken',refreshTokenSchema)};