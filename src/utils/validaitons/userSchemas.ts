import { z } from "zod";

export const registerSchema = z.object({
  email: z
    .string({
      required_error: "Email is required",
    })
    .email(),
  password: z
    .string({
      required_error: "Password is required",
    })
    .min(6, "Password must be at least 6 characters")
    .max(20)
    .refine((value) => /\d/.test(value), {
      message: "Password must include a number",
    }),
  firstName: z
    .string({
      required_error: "firstName is required",
    })
    .min(2, "firstName must be at least 2 characters")
    .max(20),
  lastName: z
    .string({
      required_error: "LastName is required",
    })
    .min(2, "LastName must be at least 2 characters")
    .max(20),
});

export const userLoginSchema = z.object({
  email: z
    .string({
      required_error: "Email is required",
    })
    .email(),
  password: z
    .string({ required_error: "Password is required" })
    .min(6, "Password doesn't match")
    .max(20)
    .refine((value) => /\d/.test(value), {
      message: "Password must include a number",
    }),
});

export const chnagePasswordSchema = z
  .object({
    oldPassword: z
      .string({
        required_error: "Password is required",
      })
      .min(6, "Password doesn't match")
      .max(20)
      .refine((value) => /\d/.test(value), {
        message: "Password must include a number",
      }),

    newPassword: z
      .string({
        required_error: "Password is required",
      })
      .min(6, "Password must contain atleast 6 charecter")
      .max(20)
      .refine((value) => /\d/.test(value), {
        message: "Password must include a number",
      }),
  })
  .refine((data) => data.oldPassword !== data.newPassword, {
    message: "New password must not be same as old password",
    path: ["newPassword"],
  });

export const UpdateUserProfileSchema = z.object({
  firstName: z
    .string()
    .min(2, "firstName must be at least 2 char")
    .max(20)
    .optional(),
  lastName: z
    .string()
    .min(2, "LastName must be at least 2 char")
    .max(20)
    .optional(),
  email: z.string({}).email().optional(),
});

export const forgotPasswordSchema = z.object({
  email: z
    .string({
      required_error: "Email is required",
    })
    .email(),
});

export const verifyForgotPasswordSchema = z.object({
  otp: z.string({
    required_error: "OTP is required",
  }),

  newPassword: z
    .string({
      required_error: "Password is required",
    })
    .min(6, "Password must contain atleast 6 charecter")
    .refine((value) => /\d/.test(value), {
      message: "Password must include a number",
    }),
});
