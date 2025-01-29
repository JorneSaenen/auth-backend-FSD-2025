import jwt from "jsonwebtoken";
import { Types } from "mongoose";
import * as ms from "ms";

interface UserPayload {
  _id: Types.ObjectId;
  email: string;
  name: string;
}

interface Params {
  user: UserPayload;
  secret: string;
  expiresIn: number | ms.StringValue | undefined;
}

export const signToken = ({ user, secret, expiresIn }: Params) => {
  const token = jwt.sign(user, secret, { expiresIn });
  return token;
};
