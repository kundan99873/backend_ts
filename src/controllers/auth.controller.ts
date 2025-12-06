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
import { decryptData, encryptData } from "../utils/utils.js";
import dayjs from "dayjs";

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
    {
      userId: encryptData({
        user_id: users[0]?.user_id,
        role_id: users[0]?.role_id,
      }),
    },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
  const refreshToken = jwt.sign(
    {
      userId: encryptData({
        user_id: users[0]?.user_id,
        role_id: users[0]?.role_id,
      }),
    },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d",
    }
  );

  const updateLoginQuery = `UPDATE user_details SET refresh_token = ?, last_login_at = NOW() WHERE user_id = ?`;

  const [updateUser] = await dbConnection.query<ResultSetHeader>(
    updateLoginQuery,
    [refreshToken, users[0]?.user_id]
  );

  if (updateUser.affectedRows === 0) {
    throw new ApiError(500, "Failed to update login info");
  }

  return res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json(new ApiResponse("Login Successfully"));
});

const googleLogin = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;

  const accessToken = jwt.sign(
    { userId: encryptData({ id: user?.user_id, role: user?.role_id }) },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
  const refreshToken = jwt.sign(
    { userId: encryptData({ id: user?.user_id, role: user?.role_id }) },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d",
    }
  );
  const updateLoginQuery = `UPDATE user_details SET refresh_token = ?, last_login_at = NOW() WHERE user_id = ?`;

  const [updateUser] = await dbConnection.query<ResultSetHeader>(
    updateLoginQuery,
    [refreshToken, user?.user_id]
  );

  if (updateUser.affectedRows === 0) {
    throw new ApiError(500, "Failed to update login info");
  }

  return res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json(new ApiResponse("Login Successfully"));
});

const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user;
  const logoutQuery = `UPDATE user_details set refresh_token = NULL where user_id = ?`;

  const [updateUser] = await dbConnection.query<ResultSetHeader>(logoutQuery, [
    userId,
  ]);

  if (updateUser.affectedRows === 0) {
    throw new ApiError(500, "Failed to update login info");
  }

  return res
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .status(200)
    .json(new ApiResponse("Logout Successfully..."));
});

const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
  const oldRefreshToken = req.cookies.refreshToken;

  if (!oldRefreshToken) throw new ApiError(401, "Refresh token missing");

  let decoded: any;
  try {
    decoded = jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET!);
  } catch (err) {
    throw new ApiError(401, "Invalid or expired refresh token");
  }

  const userId = decryptData(decoded.userId);
  if (!userId) throw new ApiError(401, "Invalid refresh token");

  const [rows] = await dbConnection.query<RowDataPacket[]>(
    "SELECT refresh_token FROM user_details WHERE user_id = ?",
    [userId]
  );

  if (!rows.length || rows[0]?.refresh_token !== oldRefreshToken) {
    throw new ApiError(401, "Refresh token does not match");
  }

  const encryptedUserId = encryptData(userId);

  const accessToken = jwt.sign(
    { userId: encryptedUserId },
    process.env.ACCESS_TOKEN_SECRET!,
    { expiresIn: "15m" }
  );

  const newRefreshToken = jwt.sign(
    { userId: encryptedUserId },
    process.env.REFRESH_TOKEN_SECRET!,
    { expiresIn: "7d" }
  );

  const [updateUser] = await dbConnection.query<ResultSetHeader>(
    `UPDATE user_details SET refresh_token = ?, last_login_at = NOW() WHERE user_id = ?`,
    [newRefreshToken, userId]
  );

  if (updateUser.affectedRows === 0)
    throw new ApiError(500, "Failed to update refresh token");

  return res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json(new ApiResponse("Token Refreshed Successfully"));
});

const verifyEmailAddress = asyncHandler(async (req: Request, res: Response) => {
  const token = req.body.verifyToken;

  const userDetailsQuery = `SELECT ud.user_id, ud.verify_token_expiry FROM user_details ud where ud.verify_token = ?`;
  const [user] = await dbConnection.query<RowDataPacket[]>(userDetailsQuery, [
    token,
  ]);
  const userId = user[0]?.user_id;

  if (user.length < 0) throw new ApiError(401, "Invalid token or expired");

  if (dayjs() < user[0]?.verify_token_expiry) {
    const verifyToken = crypto.randomBytes(20).toString("hex");

    const updateTokenQuery = `UPDATE user_details SET verify_token = ?, verify_token_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE)) WHERE user_id = ?`;
    const [updateUser] = await dbConnection.query<ResultSetHeader>(
      updateTokenQuery,
      [verifyToken, userId]
    );

    if (updateUser.affectedRows === 0)
      throw new ApiError(500, "Failed to update token");

    throw new ApiError(401, "Invalid token or expired");
  }
});

const changePassword = asyncHandler(async (req: Request, res: Response) => {
  const { password, new_password } = req.body;

  const getUserQuery = `SELECT ud.password FROM user_details ud WHERE ud.user_id = ?`;

  const [user] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
    req.user?.user_id,
  ]);
  const prevPassword = user[0]?.password;

  const comparePass = bcrypt.compare(password, prevPassword);

  if (!comparePass) throw new ApiError(401, "Incorrect Previous Password");

  const hashedPassword = await bcrypt.hash(new_password, 10);
  const updatePassQuery = `UPDATE user_details SET password = ? WHERE user_id = ?`;

  const [updatePassword] = await dbConnection.query<ResultSetHeader>(
    updatePassQuery,
    [hashedPassword, req.user?.user_id]
  );
  if (updatePassword.affectedRows === 0)
    throw new ApiError(400, "Failed to update the password");

  return res
    .status(200)
    .json(new ApiResponse("Password Updated Successfully!!!"));
});

const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;

  if(!email) throw new ApiError(401, "Email Address is required");
  const getUserQuery = `SELECT user_id FROM user_details WHERE email =  ?`;
  const [user] = await dbConnection.query<RowDataPacket[]>(
    getUserQuery,
    email
  );

  if(user.length == 0) throw new ApiError(401, "Email Address not found");

    const forgotPasswordToken = crypto.randomBytes(20).toString("hex");

    const forgotQuery = `UPDATE user_details SET forgot_password_token = ?, forgot_password_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE ud.email = ?`;

    const [updateUser] = await dbConnection.query<ResultSetHeader>(forgotQuery, [forgotPasswordToken, email]);

    if(updateUser.affectedRows === 0) throw new ApiError(400, "");





});

export {
  registerUser,
  loginUser,
  googleLogin,
  logoutUser,
  refreshAccessToken,
  verifyEmailAddress,
  changePassword,
  forgotPassword,
};
