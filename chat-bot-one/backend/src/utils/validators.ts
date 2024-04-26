import { body, ValidationChain, validationResult } from "express-validator";
import { NextFunction, Request, Response } from "express";

export const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    for (let validation of validations) {
      const result = await validation.run(req);

      if (!result.isEmpty()) {
        const errors = validationResult(req);
        return res.status(422).json({ errors: errors.array() });
      }
    }

    // Call next() only if there are no validation errors
    next(); 
  };
};

export const loginValidator = [
  body("email").trim().isEmail().withMessage("Email is invalid"),
  body("password")
    .trim()
    .isLength({ min: 6 })
    .withMessage("Password should contain atleast 6 characters"),
];

export const signupValidator = [
  body("name").notEmpty().withMessage("Name is required"),
  ...loginValidator,
];
