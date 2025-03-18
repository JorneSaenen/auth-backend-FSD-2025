// Imports
import "dotenv/config";
import cors from "cors";
import express from "express";
import { notFound } from "./controllers/notFoundController";
import authRoutes from "./routes/authRoutes";
import todoRoutes from "./routes/todoRoutes";
import { isAuth } from "./middleware/authMiddleware";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import { MONGO_URI } from "./utils/env";
import morgan from "morgan";

// Variables
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(morgan("dev"));
app.use(cors());
app.use(cookieParser());
app.use(express.json());

// Routes
app.use("/api", authRoutes);
app.use("/api/todos", isAuth, todoRoutes);
app.all("*", notFound);

// Database connection
try {
  await mongoose.connect(MONGO_URI!);
  console.log("Database connection OK");
} catch (err) {
  console.error(err);
  process.exit(1);
}

// Server Listening
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}! 🚀`);
});
