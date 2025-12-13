import type { Request, Response } from "express";
import dbConnection from "../config/dbConnection.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/apiResponse.js";
import type { RowDataPacket } from "mysql2";

const getLoggedInUser = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.user_id;

  const getUserDetailQuery = `SELECT user_id, name, email, avatar_url FROM user_details WHERE user_id = ?`;

  const [user] = await dbConnection.query<RowDataPacket[]>(getUserDetailQuery, [
    userId,
  ]);
  return res
    .status(200)
    .json(
      new ApiResponse("User details fetched successfully", { user: user[0] })
    );
});

const getUserById = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.params.id;
  const getUserQuery = `SELECT user_id, name, email, avatar_url FROM user_details WHERE user_id = ?`;

  const [user] = await dbConnection.query<RowDataPacket[]>(getUserQuery, [
    userId,
  ]);

  return res
    .status(200)
    .json(new ApiResponse("User fetched successfully", user[0]));
});

export { getLoggedInUser, getUserById };
