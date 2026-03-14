require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");

const app = express();
const port = 4000;
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/", async (req, res) => {
  const { email, subject, message, table, order1 } = req.query;

  try {
    await resend.emails.send({
      from: "FOODco <onboarding@resend.dev>",
      to: [email, process.env.EMAIL_USER],
      subject: `${subject}'s Order`,
      html: `
        <h1>Order Summary</h1>
        <p><strong>Table number:</strong> ${table}</p>
        <p><strong>Allergies / notes:</strong> ${order1}</p>
        <h2>Your order:</h2>
        <pre>${message}</pre>
      `,
    });
    res.send("Email sent successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred sending the email.");
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
