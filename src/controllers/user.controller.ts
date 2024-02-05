import { Request as ExpressRequest, Response } from "express";
import { ApiResponse } from "../utils/ApiResponse";
import { ApiError } from "../utils/ApiError";
import { User } from "../models/user.model";
import { UserPayload } from "../../types";
import { asyncHandler } from "../utils/asyncHandler";

import {
  registerSchema,
  userLoginSchema,
  chnagePasswordSchema,
  UpdateUserProfileSchema,
  forgotPasswordSchema,
  verifyForgotPasswordSchema,
} from "../utils/validaitons/userSchemas";

import crypto from "crypto";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

interface Request extends ExpressRequest {
  user?: UserPayload;
}

const generateAccessAndRefreshTokens = async (userId: string) => {
  try {
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(400, "user not found");
    }
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({
      validateBeforeSave: false,
    });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Token generation failed");
  }
};

const UserRegister = asyncHandler(async (req: Request, res: Response) => {
  const inputData = registerSchema.safeParse(req.body);

  if (!inputData.success) {
    throw new ApiError(400, inputData.error.issues[0].message);
  }

  const { email, password, firstName, lastName } = inputData.data;

  const user = await User.findOne({
    email: email.toLowerCase(),
  });

  if (user) {
    throw new ApiError(409, "User already exists");
  }

  const newUser = await User.create({
    email: email.toLowerCase(),
    password,
    firstName,
    lastName,
  });

  const { refreshToken, accessToken } = await generateAccessAndRefreshTokens(
    newUser?._id
  );

  const createdUser = await User.findById(newUser._id).select(
    "-password -otp -otpExpires -RefreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "User not created");
  }

  const cookieOptions = {
    httpOnly: true,
    secure: true,
  };

  res
    .status(201)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(new ApiResponse(201, createdUser, "User created"));
});

const UserLogin = asyncHandler(async (req: Request, res: Response) => {
  const inputData = userLoginSchema.safeParse(req.body);

  if (!inputData.success) {
    throw new ApiError(400, inputData.error.issues[0].message);
  }

  const { email, password } = inputData.data;

  if (
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "")
  ) {
    throw new ApiError(409, "User already logged in");
  }

  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    throw new ApiError(400, "User doesn't exists!");
  }

  const isPasswordVaild = await user.isPasswordCorrect(password);

  if (!isPasswordVaild) {
    throw new ApiError(401, "Password is incorrect");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -otp -otpExpires"
  );

  const cookieOptions = {
    httpOnly: true,
    secure: true,
  };

  res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser },
        "User logged in successfully"
      )
    );
});

const UserLogout = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    throw new ApiError(401, "Unauthorized request");
  }

  await User.findByIdAndUpdate(
    req.user?._id,
    {
      $unset: { refreshToken: "" },
    },
    {
      new: true,
    }
  );

  const cookieOptions = {
    httpOnly: true,
    secure: true,
  };

  res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, null, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  const secret = process.env.REFRESH_TOKEN_SECRET;

  if (!secret) {
    throw new ApiError(400, "refresh token not found");
  }

  try {
    const decodedToken = jwt.verify(incomingRefreshToken, secret);

    if (typeof decodedToken !== "object" || !("_id" in decodedToken)) {
      throw new ApiError(401, "Invalid refresh token");
    }
    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken,
            refreshToken,
          },
          "Access token refreshed successfully"
        )
      );
  } catch (error: unknown) {
    if (error instanceof Error) {
      throw new ApiError(401, error?.message);
    } else {
      throw new ApiError(401, "Invalid refresh token");
    }
  }
});

const getUserProfile = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;

  if (!user) {
    throw new ApiError(401, "Unauthorized request");
  }

  const userProfile = await User.findById(user._id).select(
    "-password -refreshToken -otp -otpExpires"
  );

  res.status(200).json(new ApiResponse(200, userProfile, "User profile"));
});

const changeCurrentPassword = asyncHandler(
  async (req: Request, res: Response) => {
    const inputData = chnagePasswordSchema.safeParse(req.body);

    if (!inputData.success) {
      throw new ApiError(400, inputData.error.issues[0].message);
    }

    const { oldPassword, newPassword } = inputData.data;

    if (!req.user) {
      throw new ApiError(401, "Unauthorized request");
    }

    const user = await User.findById(req.user._id);

    if (!user) {
      throw new ApiError(401, "No user found");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
      throw new ApiError(401, "Password is incorrect");
    }

    user.password = newPassword;

    await user.save({
      validateBeforeSave: false,
    });

    res.status(200).json(new ApiResponse(200, null, "Password changed"));
  }
);

const UpdateUserProfile = asyncHandler(async (req: Request, res: Response) => {
  const inputData = UpdateUserProfileSchema.safeParse(req.body);

  if (!inputData.success) {
    throw new ApiError(400, inputData.error.issues[0].message);
  }

  const { firstName, lastName, email } = inputData.data;

  if (!req.user) {
    throw new ApiError(401, "Unauthorized request");
  }

  if (!firstName && !lastName && !email) {
    throw new ApiError(400, "no fields to update");
  }

  const user = await User.findById(req.user._id);

  if (!user) {
    throw new ApiError(401, "No user found");
  }

  if (firstName && firstName !== user.firstName) {
    user.firstName = firstName;
  }

  if (lastName && lastName !== user.lastName) {
    user.lastName = lastName;
  }

  if (email && email !== user.email) {
    user.email = email;
  }

  await user.save({
    validateBeforeSave: false,
  });

  res
    .status(200)
    .json(new ApiResponse(200, { updatedUser: user }, "User profile updated"));
});

const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const inputData = forgotPasswordSchema.safeParse(req.body);

  if (!inputData.success) {
    throw new ApiError(400, inputData.error.issues[0].message);
  }

  const { email } = inputData.data;

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const otp = crypto.randomBytes(4).toString("hex");

  user.otp = otp;

  // Set otpExpires to 15 minutes from now
  user.otpExpires = new Date(Date.now() + 15 * 60 * 1000);

  await user.save();

  const transporter = nodemailer.createTransport({
    service: "outlook",
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL_USERNAME,
    subject: "OTP to reset password",
    html: `
    <h1>OTP for Account Update</h1>
    <p>Hello,</p>
    <p>Your OTP for account update is <strong>${otp}</strong>.</p>
    <p>If you did not request this, please ignore this email.</p>
    <p>Best,</p>
    <p>Pulak Sarmah</p>
`,
  };

  await transporter.sendMail(mailOptions);

  res.status(200).json(new ApiResponse(200, null, "OTP sent"));
});

const varifyForgotPassword = asyncHandler(
  async (req: Request, res: Response) => {
    const inputData = verifyForgotPasswordSchema.safeParse(req.body);

    if (!inputData.success) {
      throw new ApiError(400, inputData.error.issues[0].message);
    }

    const { otp, newPassword } = inputData.data;

    const user = await User.findOne({ otp });

    if (!user) {
      throw new ApiError(400, "Invalid OTP");
    }

    if (user.otpExpires < new Date(Date.now())) {
      throw new ApiError(400, "OTP expired");
    }

    user.password = newPassword;
    user.otp = "";
    await user.save({
      validateBeforeSave: false,
    });

    const updatedUser = await User.findById(user._id).select(
      "-password -otp -otpExpires"
    );

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user?._id
    );

    const cookieOptions = {
      httpOnly: true,
      secure: true,
    };

    res
      .status(200)
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", refreshToken, cookieOptions)
      .json(
        new ApiResponse(
          200,
          { user: updatedUser },
          "Password updated successfully"
        )
      );
  }
);

export {
  UserRegister,
  UserLogin,
  UserLogout,
  refreshAccessToken,
  getUserProfile,
  changeCurrentPassword,
  UpdateUserProfile,
  forgotPassword,
  varifyForgotPassword,
};
