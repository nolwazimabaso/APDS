import https from "https";
import fs from "fs";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import accounts from "./routes/account.mjs";
import users from "./routes/user.mjs";

const PORT = 3000;
const app = express();

const options = {
    key: fs.readFileSync('keys/privatekey.pem'),
    cert: fs.readFileSync('keys/certificate.pem')
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(helmet()); // Set various security headers

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Set security headers
app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY"); // Prevents clickjacking
    res.setHeader("Content-Security-Policy", "default-src 'self'"); // CSP for XSS protection
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains"); // HSTS
    next();
});

// Generate a secret key
const secret = crypto.randomBytes(32).toString('hex');
console.log(`Generated secret: ${secret}`);

// Routes
app.use("/account", accounts);
app.use("/user", users);

let server = https.createServer(options, app);

server.listen(PORT, () => {
    console.log(`Server is running on https://localhost:${PORT}`);
});

// Handle server errors
server.on('error', (err) => {
    console.error(`Server error: ${err}`);
});
