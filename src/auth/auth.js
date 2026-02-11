import express from "express";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import crypto from "crypto";
import { Mongo } from "../database/mongo.js";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";

const collectionName = "users";
const JWT_SECRET = process.env.JWT_SECRET || "secret";

// Local Strategy (email + password)
passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        const user = await Mongo.db.collection(collectionName).findOne({ email });

        if (!user) return done(null, false);

        // user.salt deve ser Buffer
        crypto.pbkdf2(password, user.salt, 310000, 16, "sha256", (err, hashedPassword) => {
          if (err) return done(err);

          // user.password deve ser Buffer
          const stored = user.password; // Buffer
          const ok = crypto.timingSafeEqual(stored, hashedPassword);

          if (!ok) return done(null, false);

          // remove campos sensíveis
          const { password: _p, salt: _s, ...safeUser } = user;
          return done(null, safeUser);
        });
      } catch (e) {
        return done(e);
      }
    }
  )
);

const authRouter = express.Router();

// SIGNUP
authRouter.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const checkUser = await Mongo.db.collection(collectionName).findOne({ email });
    if (checkUser) {
      return res.status(409).send({
        success: false,
        statusCode: 409,
        body: { text: "User already exists" },
      });
    }

    const salt = crypto.randomBytes(16);

    crypto.pbkdf2(password, salt, 310000, 16, "sha256", async (err, hashedPassword) => {
      if (err) {
        return res.status(500).send({
          success: false,
          statusCode: 500,
          body: { text: "Error on crypto password", err: String(err) },
        });
      }

      const result = await Mongo.db.collection(collectionName).insertOne({
        email,
        password: hashedPassword, // Buffer
        salt, // Buffer
      });

      const user = await Mongo.db
        .collection(collectionName)
        .findOne({ _id: new ObjectId(result.insertedId) });

      const token = jwt.sign(
        { sub: String(user._id), email: user.email },
        JWT_SECRET,
        { expiresIn: "7d" }
      );

      return res.status(201).send({
        success: true,
        statusCode: 201,
        body: { text: "User registered correctly!", token, logged: true },
      });
    });
  } catch (e) {
    return res.status(500).send({
      success: false,
      statusCode: 500,
      body: { text: "Internal error", err: String(e) },
    });
  }
});

// LOGIN
authRouter.post("/login", (req, res, next) => {
  passport.authenticate("local", { session: false }, (error, user) => {
    if (error) {
      return res.status(500).send({
        success: false,
        statusCode: 500,
        body: { text: "Error during authentication", err: String(error) },
      });
    }

    if (!user) {
      return res.status(401).send({
        success: false,
        statusCode: 401,
        body: { text: "Invalid email or password" },
      });
    }

    const token = jwt.sign(
      { sub: String(user._id), email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).send({
      success: true,
      statusCode: 200,
      body: { text: "User logged in correctly", user, token },
    });
  })(req, res, next);
});

export default authRouter;