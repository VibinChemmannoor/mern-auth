import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../model/userModal.js';
import transporter from '../config/nodeMailer.js';

export const register = async (req,res)=>{
    const {name , email, password} = req.body;
    if(!name || !email || !password){
        return res.json({success:false,message:"Missing details"})
    }
    try {
        const isExistingUser = await userModel.findOne({email});
        if(isExistingUser){
            return res.json({success : false, message: "user already exists"});
        }
        const hashedPassword = await bcrypt.hash(password,10);
        const user = new userModel({name,email,password:hashedPassword});
        await user.save();

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge : 7 * 24 * 60 * 60 * 1000
        })
        //Sending welcome email
        const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : email,
            subject : "Welcome to mearn authentication",
            text : "Welcome to the project of mearn stack authentication project for study purpose",
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req,res)=>{
    const {email,password} = req.body;
    if(!email || !password){
        return res.json({success : false , message : "enter email and password"})
    }
    const user = await userModel.findOne({email});
    if(!user){
        return res.json({success : false , message : "Invalid email"})
    }
    const isMatch  = await bcrypt.compare(password,user.password);
    if(!isMatch){
        return res.json({success : false, message :"Invalid password"});
    }
    const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge : 7 * 24 * 60 * 60 * 1000
        })
    return res.json({success:true})

}
export const logout = async(req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === "production" ? 'none' : 'strict',
        });
        return res.json({success:true , message:"Logout successfully"})
    } catch (error) {
        return res.json({success : false, message : error.message})
    }
}

export const sendVerifyOtp = async (req, res)=>{
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success: false , message : "Account already verified"})
        }
        const otp = String (Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24*60*60*1000;
        await user.save();

         const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : user.email,
            subject : "Account verification otp",
            text : `Your OTP is ${otp} . Verify your account using this otp.`,
        }
        await transporter.sendMail(mailOptions);

        res.json({success : true, message: "Verification otp send on email."})
    } catch (error) {
        res.json({success : false , message : error.message})
    }
}

export const verifyEmail = async (req, res)=>{
    const {userId, otp} = req.body;
    if (!userId || !otp){
        return res.json ({success : false, message :"Missing details"});
    }
    try {
        const user = await userModel.findById(userId);
        if(!user){
            return res.json ({success : false, message: "User not found"});
        }
        if(user.verifyOtp === "" || user.verifyOtp !==otp){
            return res.json ({success : false, message: "Invalid otp"});
        }
        if(user.verifyOtpExpireAt < Date.now()){
            return res.json ({success : false, message: "OTP Expired"});
        }
        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({});
    } catch (error) {
        return res.json ({success : false, message :error.message});
    }
}

//check if user is authenticated
export const isAuthenticated  = async (req,res)=>{
    try {
        return res.json({success : true})
    } catch (error) {
        res.json({success : false, message : error.message})
    }
}

//send reset otp
export const sendResetOtp = async(req,res)=>{
    const {email} = req.body;
    if(!email){
        return res.json({success : false, message : 'Email is required'})
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success : false, message :"User not found"})
        }
         const otp = String (Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15*60*1000;
        await user.save();

         const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : user.email,
            subject : "Reset verification otp",
            text : `Your OTP for resetting your password is ${otp} . This otp will proceed with resetting your password.`
        }
        await transporter.sendMail(mailOptions);

        res.json({success : true, message: "Verification otp send on email."})

    } catch (error) {
        return res.json({success : true , message : error.message})
    }

}