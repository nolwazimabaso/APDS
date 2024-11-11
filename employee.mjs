import express from "express";
import db from "../db/conn.mjs";
import { ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import ExpressBrute from "express-brute";
import dotenv from 'dotenv';

// Initialize environment variables
dotenv.config();

const router = express.Router();
var store = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(store);

// Helper function to validate input
const validateInput = (username) => {
    const nameRegex = /^[A-Za-z\s]+$/; 
    
    if (!nameRegex.test(username)) {
        return { valid: false, message: "Full name can only contain letters and spaces." };
    }
    return { valid: true };
};

// Helper function to generate a random password
const generatePassword = () => {
    const length = 10;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let password = "";
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
};

// Register route
router.post("/createUser", async (req, res) => {
    const { name } = req.body;

    const validation = validateInput(name);
    if (!validation.valid) {
        return res.status(400).json({ message: validation.message });
    }

    try {
        // Generate a random password for the user
        const generatedPassword = generatePassword();

        // Hash the generated password using bcrypt
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(generatedPassword, saltRounds);

        const newDocument = {
            name,
            password: hashedPassword
        };

        // Store the user and the hashed password in the database
        let collection = await db.collection("employees");
        let result = await collection.insertOne(newDocument);

        // Respond with success message and the generated password (for the user's reference)
        res.status(201).json({ 
            message: "User created successfully", 
            userId: result.insertedId,
            generatedPassword: generatedPassword  // Include the generated password in the response
        });
    } catch (error) {
        console.error("Error during creation", error);
        res.status(500).json({ message: "Creation failed." });
    }
});

// Login route with brute force protection
router.post("/login", bruteforce.prevent, async (req, res) => {
    const { name, password } = req.body;

    try {
        // Check if the user exists in the database
        const collection = await db.collection("employees");
        const user = await collection.findOne({ name: name });

        if (!user) {
            return res.status(401).json({ message: "Unregistered User, please register first" });
        }

        // Compare the provided password with the hashed password stored in the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect password" });
        } else {
            // Authentication successful, generate JWT token
            const token = jwt.sign({ name: user.name }, process.env.JWT_SECRET, { expiresIn: "3m" });
            res.status(200).json({ message: "Login successful", token: token, name: user.name });
        }
    } catch (error) {
        console.error("Login error", error);
        res.status(500).json({ message: "Login failed." });
    }
});

export default router;
