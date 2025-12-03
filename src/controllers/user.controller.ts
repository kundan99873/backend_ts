import type { Request, Response } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import bcrypt from "bcryptjs";
import dbConnection from "../config/dbConnection.js";
import crypto from "crypto";
import { ApiError } from "../utils/apiError.js";
import { uploadMediaToCloudinary } from "../helper/uploadFileToCloudinary.js";
import type { ResultSetHeader, RowDataPacket } from "mysql2";

const registerUser = asyncHandler(async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(20).toString("hex");

  const registerUserQuery = `INSERT INTO users (name, email, password, avatar_url,verify_token, verify_token_expiry) VALUES (?, ?, ?, ?, ?, ?)`;

  const existingUserQuery = `SELECT * FROM users WHERE email = ?`;
  const [rows] = await dbConnection.query<RowDataPacket[]>(existingUserQuery, [
    email,
  ]);

  if (rows.length > 0)
    throw new ApiError(400, "User with this email already exists");

  let avatarUrl = null;

  if (req.file) {
    const result = await uploadMediaToCloudinary(req.file);
    console.log(result);
    avatarUrl = (result[0] as any).secure_url;
  }

  const result = await dbConnection.query<ResultSetHeader>(registerUserQuery, [
    name,
    email,
    hashedPassword,
    avatarUrl,
    verifyToken,
    Date.now() + 600000,
  ]);

  if (!(result as any).affectedRows)
    throw new ApiError(500, "Failed to register user");

  res.status(201).json({
    success: true,
    message: "User registered successfully",
  });
});

export { registerUser };
