import { Request, Response } from "express";
import { Todo } from "../models/TodoModel";
import { JwtPayload } from "jsonwebtoken";

interface CustomRequest extends Request {
  user: JwtPayload;
}

export const getAllTodos = async (req: CustomRequest, res: Response) => {
  try {
    const user = req.user;
    console.log(req);

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const todos = await Todo.find({ userId: user._id });
    res.status(200).json(todos);
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
