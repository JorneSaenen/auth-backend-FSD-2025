import "dotenv/config";

const { MONGO_URI, JWT_SECRET, SENDGRID_API_KEY } = process.env;

if (!MONGO_URI || !JWT_SECRET || !SENDGRID_API_KEY) {
  throw new Error("ENV is missing!");
}

export { MONGO_URI, JWT_SECRET, SENDGRID_API_KEY };
