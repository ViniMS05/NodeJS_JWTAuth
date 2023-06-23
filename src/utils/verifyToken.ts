import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export const verifyToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access Denied!" });
  }

  try {
    const secretKey = process.env.SECRET_KEY as string;

    jwt.verify(token, secretKey);

    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token!" });
  }
};
