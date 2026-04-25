const express = require("express");
const crypto = require("crypto");

const app = express();

// IMPORTANT: capture raw body
app.use(express.raw({ type: "*/*" }));

const PUBLIC_KEY = Buffer.from("MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=", "base64");

let events = [];

app.post("/webhook", (req, res) => {
    const signature = req.header("X-Signature-Ed25519");
    const timestamp = req.header("X-Signature-Timestamp");

    if (!signature || !timestamp) {
        return res.status(400).send("Missing headers");
    }

    const message = Buffer.concat([
        Buffer.from(timestamp),
        req.body
    ]);

    const isValid = crypto.verify(
        null,
        message,
        PUBLIC_KEY,
        Buffer.from(signature, "hex")
    );

    if (!isValid) {
        return res.status(401).send("Invalid signature");
    }

    const json = JSON.parse(req.body.toString());

    // store event
    events.unshift(json);

    res.status(200).send("OK");
});

app.get("/events", (req, res) => {
    res.json(events);
});

app.listen(3000, () => console.log("Server running on port 3000"));
