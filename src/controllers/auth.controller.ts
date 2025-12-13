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
import { sendTemplateEmail } from "../helper/sendMail.js";

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

  const [result] = await dbConnection.query<ResultSetHeader>(
    registerUserQuery,
    [name, email, hashedPassword, avatarUrl, verifyToken]
  );

  console.log({ result });

  if (!(result as any).affectedRows)
    throw new ApiError(500, "Failed to register user");

  const sendMail = await sendTemplateEmail({
    to: email,
    subject: "Registration Successful",
    template: "/auth/registrationSuccess.ejs",
    data: {
      name,
      year: new Date().getFullYear(),
      verifyUrl: `${
        process.env.FRONTEND_URL
      }/verify-email/token=${verifyToken}&user=${encryptData(email)}`,
    },
  });
  console.log({ sendMail });

  return res.status(201).json(new ApiResponse("User registered successfully"));
});

const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const getUserQuery = `SELECT ud.user_id, ud.email, ud.password, ud.email_verified, role_id FROM user_details ud WHERE ud.email = ?`;

  const [users] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
    email,
  ]);

  if (users.length < 1) throw new ApiError(500, "Invalid Credentials");
  const hashedPassword = users[0]?.password;

  const comparePass = await bcrypt.compare(password, hashedPassword);

  if (!comparePass) throw new ApiError(500, "Invalid Credentials");

  if (!users[0]?.email_verified) {
    const verifyToken = crypto.randomBytes(20).toString("hex");
    const updateTokenQuery = `UPDATE user_details SET verify_token = ?, verify_token_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE user_id = ?`;
    const [updateUser] = await dbConnection.query<ResultSetHeader>(
      updateTokenQuery,
      [verifyToken, users[0]?.user_id]
    );
    if (updateUser.affectedRows === 0)
      throw new ApiError(500, "Failed to update token");

    sendTemplateEmail({
      to: email,
      subject: "Verify Your Email Address",
      template: "/auth/verifyEmail.ejs",
      data: {
        name: users[0]?.name,
        year: new Date().getFullYear(),
        verifyUrl: `${process.env.FRONTEND_URL}/verify-email/token=${
          users[0]?.verify_token
        }&user=${encryptData(email)}`,
      },
    });
    throw new ApiError(500, "Please verify your email address before login");
  }

  const secretData = encryptData({
    user_id: users[0]?.user_id,
    role_id: users[0]?.role_id,
  });

  console.log({ secretData });
  const accessToken = jwt.sign(
    { data: secretData },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
  const refreshToken = jwt.sign(
    { data: secretData },
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

  const secretData = encryptData({
    user_id: user?.user_id,
    role_id: user?.role_id,
  });

  const accessToken = jwt.sign(
    { data: secretData },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );
  const refreshToken = jwt.sign(
    { data: secretData },
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
    userId?.user_id,
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

  const userDetails = decryptData(decoded);
  if (!userDetails) throw new ApiError(401, "Invalid refresh token");

  const [rows] = await dbConnection.query<RowDataPacket[]>(
    "SELECT refresh_token FROM user_details WHERE user_id = ?",
    [userDetails.user_id]
  );

  if (!rows.length || rows[0]?.refresh_token !== oldRefreshToken) {
    throw new ApiError(401, "Refresh token does not match");
  }

  const secretData = encryptData({
    user_id: userDetails?.user_id,
    role_id: userDetails?.role_id,
  });

  const accessToken = jwt.sign(
    { data: secretData },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: "15m",
    }
  );

  const newRefreshToken = jwt.sign(
    secretData,
    process.env.REFRESH_TOKEN_SECRET!,
    { expiresIn: "7d" }
  );

  const [updateUser] = await dbConnection.query<ResultSetHeader>(
    `UPDATE user_details SET refresh_token = ?, last_login_at = NOW() WHERE user_id = ?`,
    [newRefreshToken, userDetails?.user_id]
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
  const token = req.body.token;
  const email = decryptData(req.body.user);

  if (!email) throw new ApiError(401, "Invalid token or expired");
  console.log({ token, email });

  const userDetailsQuery = `SELECT (ud.verify_token_expiry < NOW()) AS is_expired, name, ud.user_id FROM user_details ud where ud.verify_token = ? AND ud.email = ?`;
  const [user] = await dbConnection.query<RowDataPacket[]>(userDetailsQuery, [
    token,
    email,
  ]);

  console.log(user);
  if (user.length === 0) throw new ApiError(401, "Invalid token or expired");

  const userId = user[0]?.user_id;

  if (user[0]?.is_expired) {
    const verifyToken = crypto.randomBytes(20).toString("hex");

    const updateTokenQuery = `UPDATE user_details SET verify_token = ?, verify_token_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE)) WHERE user_id = ?`;
    const [updateUser] = await dbConnection.query<ResultSetHeader>(
      updateTokenQuery,
      [verifyToken, userId]
    );

    if (updateUser.affectedRows === 0)
      throw new ApiError(500, "Failed to update token");

    sendTemplateEmail({
      to: email,
      subject: "Verify Your Email Address",
      template: "/auth/verifyEmail.ejs",
      data: {
        name: user[0]?.name,
        year: new Date().getFullYear(),
        verifyUrl: `${
          process.env.FRONTEND_URL
        }/verify-email/token=${verifyToken}&user=${encryptData(email)}`,
      },
    });

    throw new ApiError(401, "Invalid token or expired");
  }

  const verifyEmailQuery = `UPDATE user_details SET email_verified = 1, verify_token = NULL, verify_token_expiry = NULL WHERE user_id = ?`;
  const [verifyEmail] = await dbConnection.query<ResultSetHeader>(
    verifyEmailQuery,
    [userId]
  );
  if (verifyEmail.affectedRows === 0)
    throw new ApiError(500, "Failed to verify email address");
  return res
    .status(200)
    .json(new ApiResponse("Email Address Verified Successfully!!!"));
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

  if (!email) throw new ApiError(401, "Email address is required");
  const getUserQuery = `SELECT user_id FROM user_details WHERE email =  ?`;
  const [user] = await dbConnection.query<RowDataPacket[]>(getUserQuery, email);

  if (user.length == 0) throw new ApiError(401, "Email address not found");

  const forgotPasswordToken = crypto.randomBytes(20).toString("hex");

  const forgotQuery = `UPDATE user_details SET forgot_password_token = ?, forgot_password_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE ud.email = ?`;

  const forgotUrl = `${
    process.env.FRONTEND_URL
  }/forgot-password/token=${forgotPasswordToken}&user=${encryptData(email)}`;

  const [updateUser] = await dbConnection.query<ResultSetHeader>(forgotQuery, [
    forgotPasswordToken,
    email,
  ]);

  if (updateUser.affectedRows === 0)
    throw new ApiError(400, "Failed to update the forgot password request");

  return res
    .status(200)
    .json(
      new ApiResponse(
        "An reset password mail send to your registered email address",
        { url: forgotUrl }
      )
    );
});

const verifyPasswordToken = asyncHandler(
  async (req: Request, res: Response) => {
    const { forgot_password_token, user } = req.body;

    const email = decryptData(user || "");

    if (!forgot_password_token || !email)
      throw new ApiError(400, "Invalid Forgot Password Token");

    const getUserQuery = `SELECT ud.user_id, ud.forgot_password_expiry from user_details ud where ud.email = ? AND ud.forgot_password_token = ?`;

    if (dayjs() > user[0]?.forgot_password_expiry) {
      throw new ApiError(401, "Invalid Forgot Password Token");
    }

    const [users] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
      email,
      forgot_password_token,
    ]);

    if (users.length === 0)
      throw new ApiError(400, "Invalid Forgot Password Token");

    return res
      .status(200)
      .json(new ApiResponse("Forgot Token verified Successfully"));
  }
);

const resetPassword = asyncHandler(async (req: Request, res: Response) => {
  const { forgot_password_token, user, password } = req.body;

  const email = decryptData(user);
  if (!forgot_password_token || !email)
    throw new ApiError(400, "Invalid Forgot Password Token");
  const getUserQuery = `SELECT ud.user_id from user_details ud where ud.email = ? AND ud.forgot_password_token = ?`;

  const [users] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
    email,
    forgot_password_token,
  ]);
  if (users.length === 0)
    throw new ApiError(400, "Invalid Forgot Password Token");

  if (dayjs() > user[0]?.forgot_password_expiry) {
    throw new ApiError(401, "Invalid Forgot Password Token");
  }

  const updatePasswordQuery = `UPDATE user_details SET password = ?, forgot_password_token = NULL, forgot_password_expiry = NULL where user_id = ?`;

  const [updatePassword] = await dbConnection.query<ResultSetHeader>(
    updatePasswordQuery,
    [password, users[0]?.user_id]
  );
  if (updatePassword.affectedRows === 0)
    throw new ApiError(400, "Failed to update password");

  return res.status(200).json(new ApiResponse("Password Updated Successfully"));
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
  verifyPasswordToken,
  resetPassword,
};
