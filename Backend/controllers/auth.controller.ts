import type { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import Otp from "../models/Otp.model.ts";
import { sendOtpEmail } from "../services/email.service.ts";

import * as authService from "../services/auth.service.ts";
import User from "../models/User.model.ts";

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

type userRole = "USER" | "ADMIN";

export const generateAccessToken = ({ id, role }: { id: string; role: userRole }): string => {
  return jwt.sign({ userId: id, role: role }, process.env.JWT_SECRET || "secret", {
    expiresIn: "7d",
  });
};

export const generateRefreshToken = ({ id, role }: { id: string; role: userRole }): string => {
  return jwt.sign(
    { userId: id, role: role },
    process.env.JWT_REFRESH_SECRET || "refresh-secret",
    {
      expiresIn: "30d",
    }
  );
};

export const signupHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password, otp } = req.body;

    if (!name || !email || !password || !otp) {
      return res.status(400).json({ success: false, message: "Name, email, password, and OTP fields are all required." });
    }

    const existingUser = await authService.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ success: false, message: "An account with this email already exists." });
    }

    const otpRecord = await Otp.findOne({ email , purpose:"SIGNUP" }).sort({ createdAt: -1 });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "The verification OTP is invalid or has expired." });
    }

    const isValidOtp = await bcrypt.compare(otp, otpRecord.codeHash);
    if (!isValidOtp) {
      return res.status(401).json({ success: false, message: "Invalid verification OTP." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user: any = await authService.createUser(email, hashedPassword, name);
    
    await User.updateOne({ _id: user._id }, { $set: { isVerified: true } });
    
    user.isVerified = true;
    
    await Otp.deleteMany({ email });

    const accessToken = generateAccessToken({ id: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ id: user._id.toString(), role: user.role });

    res.status(201).json({
      success: true,
      message: "Account successfully created and verified.",
      user,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
};

export const loginHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;

    const user = await authService.findUserByEmail(email);
    if (!user || !user.hashedPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }

    const isValidPassword = await bcrypt.compare(
      password,
      user.hashedPassword
    );

    if (!isValidPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }

    const accessToken = generateAccessToken({ id: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ id: user._id.toString(), role: user.role });

    res.json({
      success: true,
      user,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
};

export const googleLoginHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { credential } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (!payload || !payload.email) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Google token provided." });
    }

    const user = await authService.findOrCreateOAuthUser(
      {
        id: payload.sub!,
        email: payload.email,
        name: payload.name,
      },
      "google"
    );

    const accessToken = generateAccessToken({ id: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ id: user._id.toString(), role: user.role });

    res.json({
      success: true,
      user,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
};

export const refreshTokenHandler = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;

    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || "refresh-secret"
    ) as { userId: string };

    const user = await authService.findUserById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists.",
      });
    }

    const accessToken = generateAccessToken(user);

    res.json({
      success: true,
      accessToken,
    });
  } catch (error) {
    res
      .status(401)
      .json({ success: false, message: "Invalid refresh token." });
  }
};

export const getCurrentUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userId = (req as any).userId;

    const user = await authService.findUserById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    res.json({
      success: true,
      user,
    });
  } catch (error) {
    next(error);
  }
};

export const logout = async (req: Request, res: Response) => {
  res.json({
    success: true,
    message: "Logged out successfully.",
  });
};

export const adminLoginHandler = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, password, adminSecret } = req.body;

    const expectedSecret = process.env.ADMIN_SIGNUP_SECRET;
    if (!expectedSecret || adminSecret !== expectedSecret) {
      return res.status(401).json({ success: false, message: "Invalid administrative secret key." });
    }

    const user = await User.findOne({ email, role: "ADMIN" });
    if (!user) {
      return res.status(404).json({ success: false, message: "Admin profile not found." });
    }

    const isMatch = await bcrypt.compare(password, user.hashedPassword || "");
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid password." });
    }

    const accessToken = generateAccessToken({ id: user._id.toString(), role: user.role });
    const refreshToken = generateRefreshToken({ id: user._id.toString(), role: user.role });

    res.json({
      success: true,
      message: "Admin login successful.",
      user: {
        email: user.email,
        name: user.name,
        role: user.role,
      },
      accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
};

export const adminSignupHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password, adminSecret } = req.body;

    const expectedSecret = process.env.ADMIN_SIGNUP_SECRET;
    if (!expectedSecret || adminSecret !== expectedSecret) {
      return res.status(401).json({ success: false, message: "Invalid administrative secret key." });
    }

    const existingAdmin = await User.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ success: false, message: "Admin profile already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = await User.create({
      name,
      email,
      hashedPassword,
      role: "ADMIN",
    });

    const accessToken = generateAccessToken({ id: admin._id.toString(), role: admin.role });
    const refreshToken = generateRefreshToken({ id: admin._id.toString(), role: admin.role });

    res.json({
      success: true,
      message: "Admin account created successfully.",
      user: admin,
      accessToken,
      refreshToken,
    });
  } catch (err) {
    next(err);
  }
};

// --- OTP SERVICE OPERATIONS ---

export const sendOtp = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email address is required." });
  }

  if (!email.endsWith("@rgipt.ac.in")) {
    return res.status(403).json({
      error: "Access restricted. Please use your official institutional email ID."
    });
  }

  try {
    const existingUser = await authService.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: "An account with this email already exists." });
    }

    await Otp.deleteMany({ email });

    const otpCode = crypto.randomInt(100000, 999999).toString();
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otpCode, salt);

    await Otp.create({
      email,
      codeHash: hashedOtp,
      purpose: "SIGNUP"
    });

    await sendOtpEmail(email, otpCode);

    return res.status(200).json({
      message: "Verification OTP generated and sent securely to your email."
    });

  } catch (error) {
    console.error("Error generating OTP:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
};

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: "Both email and OTP fields are required." });
    }

    const otpRecord = await Otp.findOne({ email }).sort({ createdAt: -1 });
    if (!otpRecord) {
      return res.status(400).json({ error: "The verification OTP is invalid or has expired." });
    }

    const isValidOtp = await bcrypt.compare(otp, otpRecord.codeHash);
    if (!isValidOtp) {
      return res.status(401).json({ error: "Invalid verification OTP." });
    }

    await Otp.findByIdAndDelete(otpRecord._id);

    return res.status(200).json({ message: "Access granted. OTP verified successfully." });

  } catch (error) {
    console.error("OTP Verification Error:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
};

export const forgotPasswordOtp = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email address is required." });
  }

  if (!email.endsWith("@rgipt.ac.in")) {
    return res.status(403).json({
      error: "Access restricted. Please use your official institutional email ID."
    });
  }

  try {
    const user = await authService.findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "No account found associated with this email address." });
    }

    // Purane reset OTPs saaf kar do
    await Otp.deleteMany({ email });

    const otpCode = crypto.randomInt(100000, 999999).toString();
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otpCode, salt);

    await Otp.create({
      email,
      codeHash: hashedOtp,
      purpose: "RESET" 
    });

    await sendOtpEmail(email, otpCode);

    return res.status(200).json({
      message: "Password reset OTP has been sent to your email."
    });

  } catch (error) {
    console.error("Forgot Password OTP Error:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: "Email, OTP, and new password fields are all required." });
    }

    const otpRecord = await Otp.findOne({ email , purpose:"RESET" }).sort({ createdAt: -1 });
    if (!otpRecord) {
      return res.status(400).json({ error: "The password reset OTP is invalid or has expired." });
    }

    const isValidOtp = await bcrypt.compare(otp, otpRecord.codeHash);
    if (!isValidOtp) {
      return res.status(401).json({ error: "Invalid verification OTP." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.updateOne({ email }, { $set: { hashedPassword } });

    await Otp.deleteMany({ email });

    return res.status(200).json({ success: true, message: "Your password has been reset successfully." });

  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(500).json({ error: "Internal server error." });
  }
};