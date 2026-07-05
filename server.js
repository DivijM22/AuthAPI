require('dotenv').config();
const express=require('express');
const mongoose=require('mongoose');
const cors=require('cors');
const cookieParser=require('cookie-parser');
const router=require('./router');

const app=express();
const port=process.env.PORT || 3000;

async function connectDB()
{
    const MONGO_URI=process.env.MONGO_URI;
    mongoose.connection.on('connected',()=>console.log("MongoDB connected"));
    mongoose.connection.on('disconnected',()=>console.log("MongoDB disconnected"));
    mongoose.connection.on('error',(err)=>console.error(`MongoDB runtime error: ${err}`));
    try{
        await mongoose.connect(MONGO_URI);
    }catch(err){
        console.error("Error connecting to MongoDB");
        console.error(err);
        process.exit(1);
    }
}

connectDB();

app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use('/myauth',router);

app.use((error,req,res,next)=>{
    const {statusCode,message}=error;
    return res.status(statusCode || 500).json({
        success : false,
        message
    });
});

app.listen(port,()=>console.log("Server is listening on port",port));