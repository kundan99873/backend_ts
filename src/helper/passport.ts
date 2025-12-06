import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dbConnection from "../config/dbConnection.js";
import type { RowDataPacket } from "mysql2";

passport.serializeUser((user: any, done) => {
  done(null, user.user_id);
});

passport.deserializeUser(async (id: number, done) => {
  const [rows] = await dbConnection.query<RowDataPacket[]>(
    "SELECT * FROM user_details WHERE user_id=?",
    [id]
  );
  done(null, (rows[0] as Express.User) || null);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value ?? null;
      const picture = profile.photos?.[0]?.value ?? null;
      const name = profile.displayName ?? "Unknown User";

      const [existingUser] = await dbConnection.query<RowDataPacket[]>(
        "SELECT * FROM user_details WHERE email=?",
        [email]
      );

      if (existingUser.length > 0) {
        return done(null, existingUser[0] as Express.User);
      }

      const [insertResult] = await dbConnection.query<any>(
        `INSERT INTO user_details (name, email, avatar_url, email_verified, refresh_token) 
         VALUES (?, ?, ?, ?)`,
        [name, email, picture, true]
      );

      const [createdUser] = await dbConnection.query<RowDataPacket[]>(
        "SELECT * FROM user_details WHERE user_id=?",
        [insertResult.insertId]
      );

      return done(null, createdUser[0] as Express.User);
    }
  )
);

export default passport;
