import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "./config.js";

export const createHash = (password) => {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};
export const isValidPassword = (user, password) => {
  return bcrypt.compareSync(password, user.password);
};
export const createToken = (payload, duration) => {
  jwt.sign(payload, config.SECRET, { expiresIn: duration });
};
export const verifyToken = (req, res, next) => {
  const headerToken = req.headers.authorization
    ? req.headers.authorization.split(" ")[1]
    : undefined;
  const cookieToken =
    req.cookies && req.cookies[`${config.APP_NAME}_cookie`]
      ? req.cookies[`${config.APP_NAME}_cookie`]
      : undefined;
  const queryToken = 
    req.query.acces_token 
      ? req.query.acces_token 
      : undefined;
  const myToken = headerToken || cookieToken || queryToken;
  if (!myToken)
    return res
      .status(401)
      .send({ origin: config.SERVER, payload: "Token no encontrado." });

  jwt.verify(myToken, config.SECRET, (err, payload) => {
    if (err)
      return res
        .status(403)
        .send({ origin: config.SERVER, payload: "Token inválido." });
    req.user = payload;
    next();
  });
};

export const verifyRequiredBody = (requiredFields) => {
  return (req, res, next) => {
    const allOk = requiredFields.every((field) => {
      return (
        req.body.hasOwnProperty(field) &&
        req.body[field] !== "" &&
        req.body[field] !== null &&
        req.body[field] !== undefined
      );
    });
    if (!allOk)
      return res
        .status(400)
        .send({ origin: config.SERVER, error: "Ingrese los demás campos." });
    next();
  };
};
