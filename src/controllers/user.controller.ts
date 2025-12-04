import type { Request, Response } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dbConnection from "../config/dbConnection.js";
import crypto from "crypto";
import { ApiError } from "../utils/apiError.js";
import { uploadMediaToCloudinary } from "../helper/uploadFileToCloudinary.js";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import { ApiResponse } from "../utils/apiResponse.js";
import { encryptData } from "../utils/utils.js";

const registerUser = asyncHandler(async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(20).toString("hex");

  const registerUserQuery = `INSERT INTO user_details (name, email, password, avatar_url,verify_token, verify_token_expiry) VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))`;

  const existingUserQuery = `SELECT * FROM user_details WHERE email = ?`;
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
  ]);

  if (!(result as any).affectedRows)
    throw new ApiError(500, "Failed to register user");

  return res.status(201).json(new ApiResponse("User registered successfully"));
});

const getUsers = asyncHandler(async (req: Request, res: Response) => {
  const search = req.query.search?.toString() || "";
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 20;

  const offset = (page - 1) * limit;

  const getUsersQuery = `
    SELECT ud.name, ud.email, ud.phone
    FROM user_details ud
    WHERE ud.name LIKE ?
    LIMIT ?
    OFFSET ?
  `;

  const [rows] = await dbConnection.query<RowDataPacket[]>(getUsersQuery, [
    `%${search}%`,
    limit,
    offset,
  ]);

  return res
    .status(200)
    .json(new ApiResponse("User Fetched Successfully", rows));
});

const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const getUserQuery = `SELECT ud.user_id, ud.email, ud.password, ud.email_verified FROM user_details ud WHERE ud.email = ?`;

  const [users] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
    email,
  ]);

  if (users.length < 1) throw new ApiError(500, "Invalid Credentials");
  const hashedPassword = users[0]?.password;

  const comparePass = await bcrypt.compare(password, hashedPassword);

  if (!comparePass) throw new ApiError(500, "Invalid Credentials");

  if (!users[0]?.email_verified)
    throw new ApiError(500, "Please verify your email address before login");

  const accessToken = jwt.sign(
    { userId: encryptData(users[0]?.user_id) },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
  const refreshToken = jwt.sign(
    { userId: encryptData(users[0]?.user_id) },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d",
    }
  );

  const updateLoginQuery = `UPDATE user_details SET refresh_token = ?, last_login_at = NOW() WHERE user_id = ?`;

  const [updateUser] = await dbConnection.query(updateLoginQuery, [
    refreshToken,
    users[0]?.user_id,
  ]);

  if ((updateUser as any).affectedRows === 0) {
    throw new ApiError(500, "Failed to update login info");
  }

  return res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    .status(200)
    .json(new ApiResponse("Login Successfully"));
});

const getUserDetailsById = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.params.id;

  const getDetailsQuery = `SELECT ud.name, ud.email, ud.avatar_url as photo from user_details ud where ud.user_id = ?`;

  const [userData] = await dbConnection.query<RowDataPacket[]>(
    getDetailsQuery,
    [userId]
  );

  if (userData.length < 1) throw new ApiError(400, "User Not Found");

  return res
    .status(200)
    .json(new ApiResponse("User Found Successfully", userData[0]));
});

const verifyEmailAddress = asyncHandler(async (req: Request, res: Response) => {
  const { verify_token, user_id } = req.body;
})

export { registerUser, getUsers, loginUser, getUserDetailsById };
