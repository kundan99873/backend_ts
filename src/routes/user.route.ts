import { Router } from "express";
import upload from "../middlewares/image.middleware.js";
import { validate } from "../middlewares/validate.middleware.js";
import { registerUserSchema } from "../validations/user.validation.js";
import {
  changePassword,
  googleLogin,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
} from "../controllers/auth.controller.js";
import verifyToken from "../middlewares/auth.middleware.js";
import passport from "../helper/passport.js";

const router = Router();

router
  .route("/register")
  .post(upload.single("avatar"), validate(registerUserSchema), registerUser);

router.route("/login").post(loginUser);
router
  .route("/google")
  .get(passport.authenticate("google", { scope: ["profile", "email"] }));
router
  .route("/google/callback")
  .get(
    passport.authenticate("google", { failureRedirect: "/login" }),
    googleLogin
  );

router.route("/refresh-token").post(refreshAccessToken);

router.use(verifyToken);
router.route("/logout").post(logoutUser);
router.route("/change-password").post(changePassword);

export default router;
