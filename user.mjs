import express from "express";
import db from "../db/conn.mjs";
import { ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import ExpressBrute from "express-brute";
import dotenv from 'dotenv';


dotenv.config();

const router = express.Router();
var store = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(store);

// Helper function to validate input
const validateInput = (name, idNumber, accountNumber, password) => {
    const nameRegex = /^[A-Za-z\s]+$/; 
    const idNumberRegex = /^\d{13}$/; 
    const accountNumberRegex = /^\d{10}$/; 
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$/; 

    if (!nameRegex.test(name)) {
        return { valid: false, message: "Full name can only contain letters and spaces." };
    }
    if (!idNumberRegex.test(idNumber)) {
        return { valid: false, message: "ID number must be 13 digits long." };
    }
    if (!accountNumberRegex.test(accountNumber)) {
        return { valid: false, message: "Account number must be 10 digits long." };
    }
    if (!passwordRegex.test(password)) {
        return { valid: false, message: "Password must be at least 8 characters long and contain uppercase, lowercase, digits, and special characters." };
    }

    return { valid: true };
};

// Register route
router.post("/register", async (req, res) => {
    const { fullname, idNumber, accountNumber, password } = req.body;

    const validation = validateInput(fullname, idNumber, accountNumber, password);
    if (!validation.valid) {
        return res.status(400).json({ message: validation.message });
    }

    try {
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newDocument = {
            fullname,
            idNumber,
            accountNumber,
            password: hashedPassword
        };

        let collection = await db.collection("customers");
        let result = await collection.insertOne(newDocument);

        res.status(201).json({ message: "User registered successfully", userId: result.insertedId });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ message: "Registration failed." });
    }
});

// Login route with brute force protection
router.post("/login", bruteforce.prevent, async (req, res) => {
    const { name, accountNumber, password } = req.body;

    try {
      const collection = await db.collection("customers");
      const user = await collection.findOne({ fullname: name });
      const account = await collection.findOne({ accountNumber: accountNumber });
  
      if (!user) {
        return res.status(401).json({ message: "Unregistered User, please register first" });
      }
      if (!account) {
        return res.status(401).json({ message: "Incorrect Account Number, please try again" });
      }
  
      // Compare the provided password with the hashed password in the database
      const passwordMatch = await bcrypt.compare(password, user.password);
  
      if (!passwordMatch) {
        return res.status(401).json({ message: "Incorrect password" });
      } else {
        // Authentication successful
        const token = jwt.sign({ fullname: user.fullname, idNumber: user.idNumber }, process.env.JWT_SECRET, { expiresIn: "3m" });
        res.status(200).json({ message: "Login successful", token: token, name: user.fullname });
      }
    } catch (error) {
        console.error("Login error", error);
        res.status(500).json({ message: "Login failed." });
    }
});

export default router;
