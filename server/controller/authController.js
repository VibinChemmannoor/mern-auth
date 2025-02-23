import bcrypt from 'bcryptjs';
import { JsonWebTokenError } from 'jsonwebtoken';
import userModel from '../model/userModal';

export const register = async (req,res)=>{
    const {name , email, password} = req.body;
    if(!name || !email || !password){
        return res.json({success:false,message:"Missing details"})
    }
    try {
        isExistingUser = await userModel.findOne({email});
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
        return res.json({success:true})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req,res)=>{
    const {name,password} = req.body;
    if(!name || !password){
        return res.json({success : false , message : "enter username and password"})
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