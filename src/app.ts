import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { ZodError, z } from "zod";

// Models

import { User } from "../models/User";
import { RegisterValidationError } from "./errors/RegisterValidationError";

// APP

const app = express();

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to the API!" });
});

dotenv.config();

// Config JSON

app.use(express.json());

// Register User

const registerBodySchema = z
  .object({
    name: z.string(),
    email: z.string().email(),
    password: z.string(),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    path: ["confirmPassword"],
    message: "Password don't match",
  });

app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password } = registerBodySchema.parse(req.body);

    const userExists = await User.findOne({ email: email });

    if (userExists) {
      return res.status(422).json({ message: "User already exists!" });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      name,
      email,
      password: passwordHash,
    });

    await user.save();

    return res.status(201).json({ message: "User created!" });
  } catch (err) {
    if (err instanceof ZodError) {
      const validationError = RegisterValidationError(err);

      return res.status(422).json(validationError);
    }
    return res
      .status(500)
      .json({ message: "Server error ocurred, try again later!" });
  }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.obujvz1.mongodb.net/NodeJSAuth?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectado ao banco!");
  })
  .catch((err) => console.log(err));
