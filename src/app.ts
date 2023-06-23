import dotenv from "dotenv";
import express, { Request, Response } from "express";
import mongoose, { isValidObjectId } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { ZodError, z } from "zod";

// Models

import { User } from "../models/User";
import { RegisterValidationError } from "./errors/RegisterValidationError";
import { verifyToken } from "./utils/verifyToken";

// APP

const app = express();

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to the API!" });
});

dotenv.config();

// Config JSON

app.use(express.json());

// Register User

const RegisterUserBodySchema = z
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

app.post("/auth/register", async (req: Request, res: Response) => {
  try {
    const { name, email, password } = RegisterUserBodySchema.parse(req.body);

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

// Login User

const LoginUserBodySchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

app.post("/auth/user", async (req: Request, res: Response) => {
  try {
    const { email, password } = LoginUserBodySchema.parse(req.body);

    const user = await User.findOne({ email: email });

    const checkPassword = await bcrypt.compare(password, user?.password || "");

    if (!user || !checkPassword) {
      return res.status(400).json({ message: "Invalid Credentials!" });
    }

    const secretKey = process.env.SECRET_KEY as string;

    const token = jwt.sign(
      {
        id: user.id,
      },
      secretKey,
      {
        expiresIn: '15m'
      }
    );

    return res.status(200).json({ message: "Authetication success!", token });
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

// Private Route

app.get("/user/:id", verifyToken, async (req: Request, res: Response) => {
  try {
    const id = req.params.id;

    const isValidId = isValidObjectId(id);

    if (!isValidId) {
      return res.status(422).json({ message: "Invalid ID!" });
    }

    const user = await User.findById(id, '-password');

    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    return res.status(200).json({ user });
  } catch (err) {
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
