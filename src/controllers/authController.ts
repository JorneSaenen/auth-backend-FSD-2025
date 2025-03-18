import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { User } from "../models/UserModel";
import { sendEmail, signToken } from "../utils/helpers";
import { BASE_URL, JWT_SECRET } from "../utils/env";
import jwt, { JwtPayload } from "jsonwebtoken";

const saltRounds = 10;

export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const verificationToken = jwt.sign({ email }, JWT_SECRET as string, {
      expiresIn: "1h",
    });

    await sendEmail({
      email,
      name,
      verifyLink: `${BASE_URL}/verify/${verificationToken}`,
    });

    const response = await User.create({
      name,
      email,
      password: hashedPassword,
      verificationToken,
    });
    if (!JWT_SECRET) {
      throw new Error("Internal error");
    }

    const user = {
      _id: response._id,
      email: response.email,
      name: response.name,
    };

    const token = signToken({
      user: user,
      secret: JWT_SECRET,
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res
      .status(201)
      .json({ message: "User created successfully", user: response });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }

    const user = await User.findOne({ email });

    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      res.status(400).json({ message: "Invalid credentials" });
      return;
    }

    if (!user.isVerified) {
      res.status(400).json({ message: "Email not verified" });
      return;
    }

    if (!JWT_SECRET) {
      throw new Error("Internal error");
    }

    const tokenUser = {
      _id: user._id,
      email: user.email,
      name: user.name,
    };
    const token = signToken({
      user: tokenUser,
      secret: JWT_SECRET,
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({ message: "User logged in successfully" });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    res.cookie("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 1,
    });

    res.status(200).json({ message: "User logged out successfully" });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const verify = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, JWT_SECRET as string);

    if (typeof decoded === "string" || !("email" in decoded)) {
      res.status(400).json({ message: "Invalid verification link." });
      return;
    }

    const user = await User.findOne({ email: decoded.email });
    if (!user) {
      res.status(400).json({ message: "Ongeldige verificatielink." });
      return;
    }
    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.json({ message: "Account geverifieerd!" });
  } catch (error) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
