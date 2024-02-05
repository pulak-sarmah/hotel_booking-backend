import { Router } from "express";
import {
  UserLogin,
  UserLogout,
  UserRegister,
  refreshAccessToken,
  getUserProfile,
  changeCurrentPassword,
  UpdateUserProfile,
  forgotPassword,
  varifyForgotPassword,
} from "../controllers/user.controller";
import { varifyJWT } from "../middleware/auth.middleware";

const router = Router();

router.route("/register").post(UserRegister);
router.route("/login").post(UserLogin);
router.route("/refresh-token").post(refreshAccessToken);

//secure route
router.route("/logout").get(varifyJWT, UserLogout);
router.route("/profile").get(varifyJWT, getUserProfile);
router.route("/change-password").post(varifyJWT, changeCurrentPassword);
router.route("/update-profile").patch(varifyJWT, UpdateUserProfile);
router.route("/forgot-password").post(forgotPassword);
router.route("/verify-forgot-password").post(varifyForgotPassword);

export default router;
