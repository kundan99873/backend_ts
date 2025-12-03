import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

const dbHost: string | undefined = process.env.DB_HOST;
const dbUser: string | undefined = process.env.DB_USER;
const dbPassword: string | undefined = process.env.DB_PASSWORD;
const dbName: string | undefined = process.env.DB_NAME;

if (!dbHost || !dbUser || !dbPassword || !dbName) {
  throw new Error(
    "Missing required environment variables: DB_HOST, DB_USER, DB_PASSWORD, or DB_NAME"
  );
}

const dbConnection = mysql.createPool({
  host: dbHost,
  user: dbUser,
  password: dbPassword,
  database: dbName,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

export default dbConnection;
