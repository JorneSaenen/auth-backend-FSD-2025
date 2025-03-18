import jwt from "jsonwebtoken";
import { Types } from "mongoose";
import * as ms from "ms";
import sgMail from "@sendgrid/mail";
import { FROM_EMAIL, SENDGRID_API_KEY, SENDGRID_TEMPLATE_ID } from "./env";

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

interface MailData {
  email: string;
  name: string;
  verifyLink: string;
}

interface MailContent {
  type: string;
  value: string;
}

export const signToken = ({ user, secret, expiresIn }: Params) => {
  const token = jwt.sign(user, secret, { expiresIn });
  return token;
};

export const sendEmail = async (data: MailData) => {
  sgMail.setApiKey(SENDGRID_API_KEY as string);
  try {
    const msg = {
      from: FROM_EMAIL as string,
      template_id: SENDGRID_TEMPLATE_ID,
      personalizations: [
        {
          to: [
            {
              email: data.email,
            },
          ],
          dynamic_template_data: {
            ...data,
            date: new Date().toLocaleDateString("nl-BE"),
          },
        },
      ],
      content: [
        {
          type: "text/html",
          value: "<p>This is a placeholder content.</p>",
        },
      ] as [MailContent],
    };
    JSON.stringify(msg.personalizations);
    await sgMail.send(msg);
  } catch (error) {
    console.error(error);
  }
};
