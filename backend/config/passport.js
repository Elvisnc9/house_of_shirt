import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User from "../models/user.model.js";
import { createClient } from 'redis';
import dotenv from "dotenv";

dotenv.config();

// Redis Client Setup (modern syntax)
const redisClient = createClient({
  url: `redis://${process.env.UPSTASH_REDIS_USER}:${process.env.UPSTASH_REDIS_PASSWORD}@${process.env.UPSTASH_REDIS_ENDPOINT}:${process.env.UPSTASH_REDIS_PORT}`,
  socket: {
    reconnectStrategy: (attempts) => Math.min(attempts * 100, 5000),
    tls: process.env.NODE_ENV === 'production' // Enable TLS only in production
  }
});

// Redis Error Handling
redisClient.on('error', (err) => console.error('Redis Client Error:', err));
redisClient.on('connect', () => console.log('Redis connected'));
redisClient.on('reconnecting', () => console.log('Redis reconnecting'));

(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error('Redis connection failed:', err);
  }
})();

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:9000/api/users/auth/google/callback",
      scope: ["profile", "email"],
      passReqToCallback: true // Optional: gives access to req object
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Validate profile email exists
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error("No email found in Google profile"));
        }

        // Check for existing user
        const existingUser = await User.findOne({
          $or: [
            { googleId: profile.id },
            { email: email }
          ]
        });

       
        if (existingUser) {
          // Merge accounts if user signed up with email first
          if (!existingUser.googleId) {
            existingUser.googleId = profile.id;
            await existingUser.save();
          }
          return done(null, existingUser);
        }

       
        const newUser = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: email,
          authMethod: 'google' // Track auth method
        });

        return done(null, newUser);
      } catch (error) {
        console.error('Google OAuth Error:', error);
        return done(error);
      }
    }
  )
);

// Serialize/Deserialize with Redis caching
passport.serializeUser((user, done) => {
  done(null, user._id.toString()); // Ensure ID is string
});

passport.deserializeUser(async (id, done) => {
  const cacheKey = `user:${id}`;
  
  try {
    // Try cache first
    const cachedUser = await redisClient.get(cacheKey);
    if (cachedUser) {
      return done(null, JSON.parse(cachedUser));
    }

    // Fallback to database
    const user = await User.findById(id);
    if (!user) {
      return done(new Error("User not found"));
    }

    // Cache user for 1 hour
    await redisClient.setEx(cacheKey, 3600, JSON.stringify(user.toObject()));
    return done(null, user);
    
  } catch (error) {
    console.error('Deserialization Error:', error);
    return done(error);
  }
});

export default passport;
