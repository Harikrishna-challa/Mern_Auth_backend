import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import authMiddleware from "../middleware/authMiddleware.js";

dotenv.config();

const router = express.Router();

// 📌 Setup Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false, // ⚠️ Allow self-signed certificate
  },
});

// ✅ Verify transporter (logs if Gmail setup is valid)
transporter.verify(function (error, success) {
  if (error) {
    console.error("Nodemailer transporter error:", error.message);
  } else {
    console.log("Nodemailer is ready to send emails ✅");
  }
});

// 📌 REGISTER USER
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "All fields are required" });

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error in Register Route:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// 📌 LOGIN USER
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, name: user.name });
  } catch (error) {
    console.error("Error in Login Route:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// 📌 FORGOT PASSWORD - SEND RESET LINK
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;

    // ✅ Wrap sendMail in try-catch to capture real errors
    try {
      await transporter.sendMail({
        from: process.env.EMAIL,
        to: email,
        subject: "Password Reset Request",
        html: `<p>Hello ${user.name},</p>
               <p>You requested a password reset. Click <a href="${resetLink}">here</a> to reset your password.</p>
               <p>This link will expire in 15 minutes.</p>`,
      });

      res.json({ message: "Password reset email sent!" });
    } catch (mailError) {
      console.error("❌ Failed to send email:", mailError.message);
      return res.status(500).json({ message: "Email sending failed", error: mailError.message });
    }
  } catch (error) {
    console.error("Error in Forgot Password Route:", error.message);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// 📌 RESET PASSWORD - UPDATE NEW PASSWORD
router.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password) return res.status(400).json({ message: "New password is required" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    res.json({ message: "Password updated successfully!" });
  } catch (error) {
    console.error("Error in Reset Password Route:", error.message);
    res.status(400).json({ message: "Invalid or expired token", error: error.message });
  }
});

// 📌 DELETE ACCOUNT
router.delete("/delete-account", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    await User.findByIdAndDelete(userId);
    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Error in Delete Account Route:", error.message);
    res.status(500).json({ message: "Server error while deleting account" });
  }
});

export default router;
