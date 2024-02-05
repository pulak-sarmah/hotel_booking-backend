import { Schema, model, Document } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
export interface IUser extends Document {
  _id: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  refreshToken: string;
  otp: string;
  otpExpires: Date;
  isPasswordCorrect(password: string): Promise<boolean>;
  generateAccessToken(): string;
  generateRefreshToken(): string;
}

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    password: { type: String, required: true },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    refreshToken: {
      type: String,
    },
    otp: {
      type: String,
      default: null,
      index: true,
    },
    otpExpires: {
      type: Date,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password: string) {
  return await bcrypt.compare(password, this.password);
};

const accesTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

if (!accesTokenSecret) {
  throw new Error("ACCESSTOKEN_TOKEN_SECRET is not defined");
}
if (!refreshTokenSecret) {
  throw new Error("REFRESHTOKEN_TOKEN_SECRET is not defined");
}

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      firstName: this.firstName,
      lastName: this.lastName,
    },
    accesTokenSecret,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRE,
    }
  );
};
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    refreshTokenSecret,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRE,
    }
  );
};

export const User = model<IUser>("User", userSchema);
