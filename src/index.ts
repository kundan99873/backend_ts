import express, { type NextFunction, type Request } from "express";
import morgan from "morgan";
import compression from "compression";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import passport from "./helper/passport.js";
import session from "express-session";

import errorMiddleware from "./middlewares/error.middleware.js";
import userRouter from "./routes/user.route.js";
import { ApiError } from "./utils/apiError.js";
import corsConfig from "./config/corsConfig.js";
import { fileURLToPath } from "url";
import path from "path";

const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", true);



app.use(
  session({
    secret: process.env.SESSION_SECRET || "mysecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
    },
  })
);

app.use(helmet());
app.use(compression());
app.use(corsConfig);
app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.session());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, try again later",
  })
);

if (process.env.NODE_ENV === "development") app.use(morgan("dev"));
else app.use(morgan("combined"));

app.get("/", (_, res) => {
  res.sendFile(path.join(__dirname, "views", "home/index.html"));
});

app.use("/api/users", userRouter);
app.get("/test", (req, res) => {
    res.json({
      ip: req.ip,
      ips: req.ips,
      data: req.socket.remoteAddress
    })
})

app.use((req: Request, _, next: NextFunction) => {
  next(new ApiError(404, "Route not found", { route: req.originalUrl }));
});

app.use(errorMiddleware);
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
// const startServer = async () => {
//   try {
//     await isDbConnected();
//     app.listen(PORT, () => {
//       console.log(`Server is running on http://localhost:${PORT}`);
//     });
//   } catch (err) {
//     console.error("Database connection failed:", err);
//     process.exit(1);
//   }
// };
// startServer();
