import { Router } from "express";
import upload from "../middlewares/image.middleware.js";
import { validate } from "../middlewares/validate.middleware.js";
import {
  changePasswordSchema,
  registerUserSchema,
  resetPasswordSchema,
} from "../validations/user.validation.js";
import {
  changePassword,
  forgotPassword,
  googleLogin,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resetPassword,
  verifyEmailAddress,
  verifyPasswordToken,
} from "../controllers/auth.controller.js";
import passport from "../helper/passport.js";
import {
  getLoggedInUser,
  getUserById,
} from "../controllers/user.controller.js";
import {
  verifyAdminToken,
  verifyUserToken,
} from "../middlewares/auth.middleware.js";

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
router.route("/verify-email").post(verifyEmailAddress);
router.route("/forgot-password").post(forgotPassword);
router.route("/verify-forgot").post(verifyPasswordToken);
router
  .route("/reset-password")
  .post(validate(resetPasswordSchema), resetPassword);

router.route("/get-user/:id").get(verifyAdminToken, getUserById);

router.use(verifyUserToken);
router.route("/logout").post(logoutUser);
router
  .route("/change-password")
  .post(validate(changePasswordSchema), changePassword);
router.route("/profile").post(getLoggedInUser);

export default router;
