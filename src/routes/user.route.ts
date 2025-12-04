import { Router } from "express";
import { getUserDetailsById, getUsers, loginUser, registerUser } from "../controllers/user.controller.js";
import upload from "../middlewares/image.middleware.js";
import { validate } from "../middlewares/validate.middleware.js";
import { registerUserSchema } from "../validations/user.validation.js";

const router = Router();

router.post(
  "/register",
  upload.single("avatar"),
  validate(registerUserSchema),
  registerUser
);

router.get("/get-user", getUsers);
router.post("/login", loginUser);
router.get("/get-user/:id", getUserDetailsById);

export default router;
