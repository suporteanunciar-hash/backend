import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import { createServer } from "http";
import { Server } from "socket.io";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

/* ══════════════════════════════════════
   SETUP
══════════════════════════════════════ */
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ── Middlewares ── */
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

/* ══════════════════════════════════════
   CLOUDINARY
══════════════════════════════════════ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* Storage fotos */
const storageFotos = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "anunciar/fotos",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
  },
});

/* Storage vídeos */
const storageVideos = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "anunciar/videos",
    resource_type: "video",
  },
});

const uploadFotos = multer({ storage: storageFotos });
const uploadVideos = multer({ storage: storageVideos });

/* ══════════════════════════════════════
   MONGODB
══════════════════════════════════════ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("🟢 MongoDB conectado"))
  .catch(err => {
    console.error("🔴 Erro MongoDB:", err);
    process.exit(1);
  });

/* ══════════════════════════════════════
   SCHEMAS
══════════════════════════════════════ */

const User = mongoose.model("User", new mongoose.Schema({
  nome: String,
  email: String,
  senha: String,
  telefone: String,
  fotoPerfil: String,
}));

const Anuncio = mongoose.model("Anuncio", new mongoose.Schema({
  titulo: String,
  descricao: String,
  preco: Number, // 🔥 corrigido (antes string)
  categoria: String,
  condicao: String,
  estado: String,
  cidade: String,
  fotos: Array,
  video: Object,
  whatsapp: String,
  detalhes: Object,
  usuario: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  criadoEm: { type: Date, default: Date.now }
}));

/* ══════════════════════════════════════
   AUTH
══════════════════════════════════════ */
function auth(req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ erro: "Sem token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ erro: "Token inválido" });
  }
}

/* ══════════════════════════════════════
   UPLOAD FOTOS
══════════════════════════════════════ */
app.post("/anuncios/fotos", auth, uploadFotos.array("fotos"), (req, res) => {
  try {
    if (!req.files) return res.status(400).json({ erro: "Sem arquivos" });

    const fotos = req.files.map(f => ({
      url: f.path,
      publicId: f.filename
    }));

    res.json({ fotos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro upload fotos" });
  }
});

/* ══════════════════════════════════════
   UPLOAD VIDEO
══════════════════════════════════════ */
app.post("/anuncios/video", auth, uploadVideos.single("video"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ erro: "Nenhum vídeo enviado" });
    }

    res.json({
      video: {
        url: req.file.path,
        publicId: req.file.filename
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro upload vídeo" });
  }
});

/* ══════════════════════════════════════
   CRIAR ANUNCIO (FIX PRINCIPAL)
══════════════════════════════════════ */
app.post("/anuncios", auth, async (req, res) => {
  try {
    const {
      titulo,
      descricao,
      preco,
      categoria,
      estado,
      cidade
    } = req.body;

    // 🔥 VALIDAÇÃO FORTE
    if (!titulo || !descricao || !preco || !categoria || !estado || !cidade) {
      return res.status(400).json({ erro: "Campos obrigatórios faltando" });
    }

    const anuncio = await Anuncio.create({
      ...req.body,
      preco: Number(String(preco).replace(/[^\d]/g, "")) / 100, // 🔥 FIX PREÇO
      usuario: req.userId
    });

    res.status(201).json(anuncio);

  } catch (err) {
    console.error("ERRO CRIAR:", err);
    res.status(500).json({
      erro: "Erro ao criar anúncio",
      detalhe: err.message
    });
  }
});

/* ══════════════════════════════════════
   LISTAR
══════════════════════════════════════ */
app.get("/anuncios", async (req, res) => {
  try {
    const anuncios = await Anuncio.find()
      .sort({ criadoEm: -1 });

    res.json(anuncios);
  } catch {
    res.status(500).json({ erro: "Erro ao listar" });
  }
});

/* ══════════════════════════════════════
   IA (FIX FETCH)
══════════════════════════════════════ */
import fetch from "node-fetch";

app.post("/ia/descricao", async (req, res) => {
  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 800,
        messages: [{ role: "user", content: "Gere uma descrição de produto." }]
      })
    });

    const data = await response.json();
    res.json({ descricao: data?.content?.[0]?.text || "Erro IA" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro IA" });
  }
});

/* ══════════════════════════════════════
   START
══════════════════════════════════════ */
httpServer.listen(PORT, () => {
  console.log("🚀 Rodando porta " + PORT);
});
