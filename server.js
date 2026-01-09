import express from "express";
import jwt from "jsonwebtoken";
import csrf from "csurf";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();
const app = express();

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CONFIG))
});
const db = admin.firestore();

app.use(express.json());
app.use(cookieParser());

const csrfProtection = csrf({ cookie: true });

function auth(req,res,next){
  const t=req.headers.authorization?.split(" ")[1];
  if(!t) return res.sendStatus(401);
  jwt.verify(t,"SECRET",next);
}

app.post("/api/login",(req,res)=>{
  if(req.body.user===process.env.ADMIN_USER &&
     req.body.pass===process.env.ADMIN_PASS){
    res.json({token:jwt.sign({admin:true},"SECRET",{expiresIn:"2h"})});
  } else res.sendStatus(403);
});

app.post("/api/section",auth,csrfProtection,async(req,res)=>{
  await db.collection("sections").add(req.body);
  res.sendStatus(200);
});

app.post("/api/news",auth,csrfProtection,async(req,res)=>{
  await db.collection("news").add(req.body);
  res.sendStatus(200);
});

app.get("/api/news",async(req,res)=>{
  const s=await db.collection("sections").get();
  const n=await db.collection("news").get();
  res.json(
    s.docs.map(sec=>({
      section:sec.data().name,
      news:n.docs.map(x=>x.data())
        .filter(x=>x.section===sec.data().name)
    }))
  );
});

export default app;
