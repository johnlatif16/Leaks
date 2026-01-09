import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import admin from "firebase-admin";
import cookieParser from "cookie-parser";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

/* ===============================
   Firebase Admin Initialization
================================ */
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_CONFIG)
  )
});

const db = admin.firestore();

/* ===============================
   Constants from .env
================================ */
const JWT_SECRET = process.env.JWT_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;

/* ===============================
   JWT Middleware
================================ */
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.user = decoded;
    next();
  });
}

/* ===============================
   CSRF (Double Submit Cookie)
================================ */
function generateCSRFToken() {
  return crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(crypto.randomBytes(32).toString("hex"))
    .digest("hex");
}

function csrfProtection(req, res, next) {
  const cookieToken = req.cookies.csrfToken;
  const headerToken = req.headers["x-csrf-token"];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "Invalid CSRF Token" });
  }
  next();
}

/* ===============================
   Routes
================================ */

/* ---- Get CSRF Token ---- */
app.get("/api/csrf", (req, res) => {
  const token = generateCSRFToken();
  res.cookie("csrfToken", token, {
    httpOnly: false,
    sameSite: "strict",
    secure: true
  });
  res.json({ csrfToken: token });
});

/* ---- Login ---- */
app.post("/api/login", (req, res) => {
  const { user, pass } = req.body;

  if (
    user === process.env.ADMIN_USER &&
    pass === process.env.ADMIN_PASS
  ) {
    const token = jwt.sign(
      { role: "admin" },
      JWT_SECRET,
      { expiresIn: "2h" }
    );
    return res.json({ token });
  }

  res.sendStatus(403);
});

/* ---- Add Section ---- */
app.post(
  "/api/section",
  auth,
  csrfProtection,
  async (req, res) => {
    await db.collection("sections").add({
      name: req.body.name,
      createdAt: Date.now()
    });
    res.sendStatus(200);
  }
);

/* ---- Add News ---- */
app.post(
  "/api/news",
  auth,
  csrfProtection,
  async (req, res) => {
    await db.collection("news").add({
      title: req.body.title,
      content: req.body.content,
      section: req.body.section,
      createdAt: Date.now()
    });
    res.sendStatus(200);
  }
);

/* ---- Get News (Public) ---- */
app.get("/api/news", async (req, res) => {
  const sectionsSnap = await db.collection("sections").get();
  const newsSnap = await db.collection("news").get();

  const data = sectionsSnap.docs.map(sec => ({
    section: sec.data().name,
    news: newsSnap.docs
      .map(n => n.data())
      .filter(n => n.section === sec.data().name)
  }));

  res.json(data);
});

/* ===============================
   Export for Vercel
================================ */
export default app;
      
