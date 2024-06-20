import auth from "../config/firebase-config.js";

export const VerifyToken = async (req, res, next) => {
  // Check if the authorization header exists
  if (!req.headers.authorization) {
    return res.status(401).json({ message: "Authorization header is missing" });
  }

  // Split the authorization header to extract the token
  const parts = req.headers.authorization.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ message: "Invalid authorization header format" });
  }

  const token = parts[1];

  try {
    const decodeValue = await auth.verifyIdToken(token);
    if (decodeValue) {
      req.user = decodeValue;
      return next();
    } else {
      return res.status(401).json({ message: "Unauthorized" });
    }
  } catch (e) {
    console.error("Error verifying token:", e);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const VerifySocketToken = async (socket, next) => {
  const token = socket.handshake.auth.token;

  try {
    const decodeValue = await auth.verifyIdToken(token);

    if (decodeValue) {
      socket.user = decodeValue;
      return next();
    } else {
      return next(new Error("Unauthorized"));
    }
  } catch (e) {
    console.error("Error verifying socket token:", e);
    return next(new Error("Internal Server Error"));
  }
};
