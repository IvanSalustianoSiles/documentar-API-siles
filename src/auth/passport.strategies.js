import passport from "passport";
import local from "passport-local";
import GitHubStrategy from "passport-github2";
import jwt from "passport-jwt";
import { UserMDBManager } from "../dao/index.js";
import { isValidPassword, createHash } from "../utils.js";
import config from "../config.js";

const localStrategy = local.Strategy;
const jwtStrategy = jwt.Strategy;
const jwtExtractor = jwt.ExtractJwt;

const cookieExtractor = (req) => {
  let token = null;
  if (req && req.cookies) token = req.cookies[`${config.APP_NAME}_cookie`];
  return token;
};

const initAuthStrategies = () => {
  passport.use(
    "login",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        try {
          let myUser = await UserMDBManager.findUser(username);
          const validation = isValidPassword(myUser, password);
          if (myUser && validation) {
            return done(null, myUser);
          } else {
            return done("Error 401: Datos de acceso no válidos.", false);
          }
        } catch (error) {
          return done(error, false);
        }
      }
    )
  );
  passport.use(
    "register",
    new localStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        try {
          let user = await UserMDBManager.findUser(username);
          if (user) {
            return done(null, false);
          }
          const newUser = { ...req.body, password: createHash(password) };
          let result = await UserMDBManager.addUser(newUser);
          return done(null, newUser);
        } catch (error) {
          return done("Error:" + error);
        }
      }
    )
  );
  passport.use(
    "ghlogin",
    new GitHubStrategy(
      {
        clientID: config.GITHUB_CLIENT_ID,
        clientSecret: config.GITHUB_CLIENT_SECRET,
        callbackURL: config.GITHUB_CALLBACK_URL,
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          const email = profile._json?.email || null;
          if (email) {
            const foundUser = await UserMDBManager.findUser(email);
            if (!foundUser) {
              let completeName = profile._json.name.split(" ");
              let last = completeName.pop();
              let first = completeName.join(" ");
              const newUser = {
                name: first,
                lastName: last,
                email: email,
                password: "none",
              };
              const addingUser = await UserMDBManager.addUser(newUser);
              return done(null, addingUser);
            } else {
              console.log("Usuario previamente registrado.");
              return done(null, foundUser);
            }
          } else {
            return done(new Error("Faltan datos del perfil"), null);
          }
        } catch (error) {
          return done("Error:" + error);
        }
      }
    )
  );
  passport.use(
    "jwtlogin",
    new jwtStrategy(
      {
        jwtFromRequest: jwtExtractor.fromExtractors([cookieExtractor]),
        secretOrKey: config.SECRET,
      },
      async (jwt_payload, done) => {
        try {
          return done(null, jwt_payload);
        } catch (error) {
          return done("Error: " + error);
        }
      }
    )
  );
  passport.serializeUser((user, done) => {
    done(null, user);
  });
  passport.deserializeUser((user, done) => {
    done(null, user);
  });
};

export default initAuthStrategies;
