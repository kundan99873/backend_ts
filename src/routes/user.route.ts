import { Router } from "express";
import upload from "../middlewares/image.middleware.js";
import { validate } from "../middlewares/validate.middleware.js";
import { registerUserSchema } from "../validations/user.validation.js";
import { loginUser, logoutUser, refreshAccessToken, registerUser } from "../controllers/auth.controller.js";
import verifyToken from "../middlewares/auth.middleware.js";

const router = Router();

router
  .route("/register")
  .post(upload.single("avatar"), validate(registerUserSchema), registerUser);

router.route("/login").post(loginUser);
router.route("/refresh-token").post(refreshAccessToken);

router.use(verifyToken);
router.route("/logout").post(logoutUser);

export default router;
