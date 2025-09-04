import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET || "secret";

export const signToken = (payload: object) => {
    return jwt.sign(payload, secret, { expiresIn: "7d" });
};

export const verifyToken = (token: string) => {
    try {
        return jwt.verify(token, secret);
    } catch {
        return null;
    }
};
