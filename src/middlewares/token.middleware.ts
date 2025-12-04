import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/apiError.js";
import { decryptData } from "../utils/utils.js";

const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) throw new ApiError(401, "Access denied, token missing");

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!) as any;

    const userId = decryptData(decoded.userId);

    req.body.userId = userId;
    next();
  } catch (error) {
    next(new ApiError(401, "Invalid or expired token"));
  }
};

export default verifyToken;
