import { Request, Response } from "express";
import { Error as MongooseError } from "mongoose";
import bcrypt from "bcrypt";
import { User } from "../models/UserModel";
import { signToken } from "../utils/helpers";

const saltRounds = 10;
const SECRET = process.env.JWT_SECRET;

export const register = async (req: Request, res: Response) => {
  // This function creates a new user when the `/register` endpoint is hit.
  // It takes in a request and response object as arguments.
  try {
    // Destructure the request body into name, email, and password.
    // If any of these fields are missing, return a 400 status and an
    // error message.
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }

    // Hash the user's password using bcrypt. This is a
    // one-way encryption, so we can't reverse it.
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user in the database using the User model.
    // The `create` method is a Mongoose method that takes an object
    // and creates a new document in the database with the fields
    // specified in the object.
    const response = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    // If the JWT_SECRET environment variable is not set, throw an
    // error. This is a security risk, as it would allow anyone to
    // create a JWT token and access the API.
    if (!SECRET) {
      throw new Error("Internal error");
    }

    // Create a new user object that we will use to generate the JWT.
    // This object will contain the user's ID, email, and name.
    const user = {
      _id: response._id,
      email: response.email,
      name: response.name,
    };

    // Generate a JWT token using the signToken function. This function
    // takes the user object and the JWT_SECRET as arguments.
    const token = signToken({
      user: user,
      secret: SECRET,
      expiresIn: "7d",
    });

    // Set a cookie with the token, accessible only via HTTP, secure in production
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Return a 201 status (created) and the user object.
    res
      .status(201)
      .json({ message: "User created successfully", user: response });
  } catch (error: unknown) {
    // If an error occurs, catch it and return a 500 status with an
    // error message.
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    // Destructure email and password from the request body
    const { email, password } = req.body;

    // Check if email and password are provided, return 400 error if not
    if (!email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }

    // Find the user in the database by email
    const user = await User.findOne({ email });

    // If user is not found, return 400 error
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }

    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);

    // If passwords do not match, return 400 error
    if (!isMatch) {
      res.status(400).json({ message: "Invalid credentials" });
      return;
    }

    // Ensure the SECRET environment variable is set
    if (!SECRET) {
      throw new Error("Internal error");
    }

    // Create a user object for the token
    const tokenUser = {
      _id: user._id,
      email: user.email,
      name: user.name,
    };

    // Generate a JWT token with the user object, secret, and expiration
    const token = signToken({
      user: tokenUser,
      secret: SECRET,
      expiresIn: "7d",
    });

    // Set a cookie with the token, accessible only via HTTP, secure in production
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Respond with a success message
    res.status(200).json({ message: "User logged in successfully" });
  } catch (error: unknown) {
    // Handle any errors during the process and respond with a 500 error
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    // Set the token to an empty string, and set the maxAge to 1, which
    // means the cookie will expire in 1 second.
    res.cookie("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 1,
    });

    // Respond with a success message
    res.status(200).json({ message: "User logged out successfully" });
  } catch (error: unknown) {
    // Handle any errors that may occur during the logout process
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
