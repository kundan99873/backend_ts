import express from "express";
import morgan from "morgan";
import compression from "compression";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import errorMiddleware from "./middlewares/error.middleware.js";
import userRouter from "./routes/user.route.js";
import { ApiError } from "./utils/apiError.js";
import corsConfig from "./config/corsConfig.js";


const PORT = process.env.PORT || 3000;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(helmet());
app.use(compression());
app.use(corsConfig);
app.use(cookieParser())
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
  res.send("Hello, World!");
});

app.use("/api/users", userRouter);

app.use((req, _, next) => {
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
