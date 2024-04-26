import User from "../models/User.js";
import { NextFunction, Request, Response } from "express";
import { hash, compare } from "bcrypt";
import { createToken } from "../utils/token-manager.js";
import { COOKIE_NAME } from "../utils/constants.js";

export const getAllUsers = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const users = await User.find();
    return res.status(200).json({ message: "OK", users });
  } catch (error) {
    console.log("Error", error);
    return res.status(200).json({ message: "ERROR", cause: error.message });
  }
};

export const userSignup = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password } = req.body; // Destructure the request body into relevant fields

    const existingUser = await User.findOne({ email }); // Check the user doesnt already have an account
    if (existingUser) {
      return res.status(401).send("User already registered");
    }

    const hashedPassword = await hash(password, 10); // encrypt the password
    const user = new User({ name, email, password: hashedPassword }); // create user model
    await user.save(); // save user to database

    // Create and store cookie
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      domain: "localhost",
      signed: true,
      path: "/",
    });

    // Create JWT token, add to response
    const token = createToken(user._id.toString(), user.email, "7d");
    const expires = new Date();
    expires.setDate(expires.getDate() + 7);
    res.cookie(COOKIE_NAME, token, {
      path: "/",
      domain: "localhost",
      expires,
      httpOnly: true,
      signed: true,
    }); // need to change domain in production builds

    return res.status(201).json({ message: "OK", id: user._id.toString() });
  } catch (error) {
    console.log("Error", error);
    return res.status(200).json({ message: "ERROR", cause: error.message });
  }
};

export const userLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send("User does not exist");
    }

    const isPasswordCorrect = await compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(403).send("Incorrect password");
    }

    // Remove cookie storing an auth token from a previous session, if there is one
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      domain: "localhost",
      signed: true,
      path: "/",
    });

    // Create JWT token, add to response
    const token = createToken(user._id.toString(), user.email, "7d");
    const expires = new Date();
    expires.setDate(expires.getDate() + 7);
    res.cookie(COOKIE_NAME, token, {
      path: "/",
      domain: "localhost",
      expires,
      httpOnly: true,
      signed: true,
    }); // need to change domain in production builds

    return res.status(201).json({ message: "OK", id: user._id.toString() });
  } catch (error) {
    console.log("Error", error);
    return res.status(200).json({ message: "ERROR", cause: error.message });
  }
};
