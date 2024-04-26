import { body, validationResult } from "express-validator";
export const validate = (validations) => {
    return async (req, res, next) => {
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
//# sourceMappingURL=validators.js.map