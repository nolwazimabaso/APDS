import express from "express";
import db from "../db/conn.mjs";
import { ObjectId } from "mongodb";

const router = express.Router();

// Regular expressions for validation
const amountPattern = /^\d+(\.\d{1,2})?$/; 
const currencyPattern = /^[A-Z]{3}$/; 
const providerPattern = /^[\w\s-]+$/; 

const validateInput = (amount, currency, provider) => {
    return (
        amountPattern.test(amount) &&
        currencyPattern.test(currency) &&
        providerPattern.test(provider)
    );
};

// Get all the records
router.get("/", async (req, res) => {
    let collection = await db.collection("account");
    let results = await collection.find({}).toArray();
    res.status(200).send(results);
});

// Create a new account record
router.post("/save", async (req, res) => {
    const { amount, currency, provider } = req.body;

    // Validate the input
    if (!validateInput(amount, currency, provider)) {
        return res.status(400).send({ error: "Invalid input." });
    }

    let newDocument = {
        amount: parseFloat(amount),
        currency: currency.toUpperCase(),
        provider: provider.trim(),
    };

    let collection = await db.collection("account");
    let results = await collection.insertOne(newDocument);
    res.status(201).send(results);    
});

export default router;
