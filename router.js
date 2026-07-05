const express=require('express');
const { signupUser, loginUser, refreshSession, getUserInformation, logoutUser, authMiddleware } = require('./controller');
const router=express.Router();

router.post('/signup',signupUser);
router.post('/login',loginUser);
router.get('/refresh',refreshSession);
router.get('/me',authMiddleware,getUserInformation);
router.get('/logout',logoutUser);

module.exports=router;