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
const app        = express();
const httpServer = createServer(app);
const io         = new Server(httpServer, {
  cors: { origin: process.env.FRONTEND_URL || "*", methods: ["GET","POST"] }
});

const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

/* ── Middlewares ── */
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

/* ══════════════════════════════════════
   CLOUDINARY
══════════════════════════════════════ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* Storage para fotos */
const storageFotos = new CloudinaryStorage({
  cloudinary,
  params: {
    folder:         "anunciar/fotos",
    allowed_formats: ["jpg","jpeg","png","webp"],
    transformation: [{ width: 1200, height: 900, crop: "limit", quality: "auto" }],
  },
});

/* Storage para vídeos */
const storageVideos = new CloudinaryStorage({
  cloudinary,
  params: {
    folder:         "anunciar/videos",
    resource_type:  "video",
    allowed_formats: ["mp4","mov","avi","webm"],
  },
});

const uploadFotos  = multer({ storage: storageFotos,  limits: { fileSize: 5  * 1024 * 1024, files: 10 } });
const uploadVideos = multer({ storage: storageVideos, limits: { fileSize: 500 * 1024 * 1024, files: 1  } });

/* ══════════════════════════════════════
   MONGODB
══════════════════════════════════════ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("🟢 MongoDB conectado"))
  .catch(err => { console.error("🔴 Erro MongoDB:", err); process.exit(1); });

/* ══════════════════════════════════════
   SCHEMAS
══════════════════════════════════════ */

/* ── Usuário ── */
const UserSchema = new mongoose.Schema({
  nome:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  senha:     { type: String, required: true },
  telefone:  { type: String, default: "" },
  fotoPerfil:{ type: String, default: "" },
  criadoEm: { type: Date, default: Date.now },
});
const User = mongoose.model("User", UserSchema);

/* ── Anúncio ── */
const AnuncioSchema = new mongoose.Schema({
  titulo:    { type: String, required: true, trim: true },
  descricao: { type: String, required: true },
  preco:     { type: String, required: true },
  categoria: { type: String, required: true },
  condicao:  { type: String, default: "usado" },
  estado:    { type: String, required: true },
  cidade:    { type: String, required: true },
  fotos:     [{ url: String, publicId: String }],
  video:     { url: String, publicId: String },
  whatsapp:  { type: String, default: "" },
  detalhes:  { type: mongoose.Schema.Types.Mixed, default: {} },
  usuario:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  ativo:     { type: Boolean, default: true },
  views:     { type: Number, default: 0 },
  criadoEm: { type: Date, default: Date.now },
});
AnuncioSchema.index({ titulo: "text", descricao: "text" });
const Anuncio = mongoose.model("Anuncio", AnuncioSchema);

/* ── Mensagem ── */
const MensagemSchema = new mongoose.Schema({
  conversa:  { type: String, required: true }, // "userId1_userId2_anuncioId"
  de:        { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  para:      { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  anuncio:   { type: mongoose.Schema.Types.ObjectId, ref: "Anuncio" },
  texto:     { type: String, required: true },
  lida:      { type: Boolean, default: false },
  criadoEm: { type: Date, default: Date.now },
});
const Mensagem = mongoose.model("Mensagem", MensagemSchema);

/* ══════════════════════════════════════
   MIDDLEWARE DE AUTENTICAÇÃO
══════════════════════════════════════ */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }
  try {
    const decoded = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ erro: "Token inválido ou expirado" });
  }
}

/* ══════════════════════════════════════
   ROTAS — AUTH
══════════════════════════════════════ */

/* POST /auth/register */
app.post("/auth/register", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha)
      return res.status(400).json({ erro: "Preencha todos os campos" });

    if (senha.length < 6)
      return res.status(400).json({ erro: "Senha deve ter pelo menos 6 caracteres" });

    const existe = await User.findOne({ email });
    if (existe)
      return res.status(400).json({ erro: "E-mail já cadastrado" });

    const senhaHash = await bcrypt.hash(senha, 12);
    const user = await User.create({ nome, email, senha: senhaHash });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      token,
      usuario: { id: user._id, nome: user.nome, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro ao criar conta" });
  }
});

/* POST /auth/login */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha)
      return res.status(400).json({ erro: "Preencha e-mail e senha" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ erro: "E-mail não cadastrado" });

    const ok = await bcrypt.compare(senha, user.senha);
    if (!ok)
      return res.status(400).json({ erro: "Senha incorreta" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      usuario: { id: user._id, nome: user.nome, email: user.email, fotoPerfil: user.fotoPerfil },
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro ao fazer login" });
  }
});

/* GET /auth/me — retorna dados do usuário logado */
app.get("/auth/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-senha");
    if (!user) return res.status(404).json({ erro: "Usuário não encontrado" });
    res.json(user);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar usuário" });
  }
});

/* PUT /auth/perfil — atualiza perfil */
app.put("/auth/perfil", auth, async (req, res) => {
  try {
    const { nome, telefone } = req.body;
    const user = await User.findByIdAndUpdate(
      req.userId,
      { nome, telefone },
      { new: true, runValidators: true }
    ).select("-senha");
    res.json(user);
  } catch {
    res.status(500).json({ erro: "Erro ao atualizar perfil" });
  }
});

/* PUT /auth/senha — altera senha */
app.put("/auth/senha", auth, async (req, res) => {
  try {
    const { senhaAtual, novaSenha } = req.body;
    const user = await User.findById(req.userId);

    const ok = await bcrypt.compare(senhaAtual, user.senha);
    if (!ok) return res.status(400).json({ erro: "Senha atual incorreta" });

    if (novaSenha.length < 6)
      return res.status(400).json({ erro: "Nova senha deve ter pelo menos 6 caracteres" });

    user.senha = await bcrypt.hash(novaSenha, 12);
    await user.save();
    res.json({ mensagem: "Senha alterada com sucesso" });
  } catch {
    res.status(500).json({ erro: "Erro ao alterar senha" });
  }
});

/* POST /auth/foto-perfil */
app.post("/auth/foto-perfil", auth, uploadFotos.single("foto"), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.userId,
      { fotoPerfil: req.file.path },
      { new: true }
    ).select("-senha");
    res.json(user);
  } catch {
    res.status(500).json({ erro: "Erro ao atualizar foto" });
  }
});

/* ══════════════════════════════════════
   ROTAS — ANÚNCIOS
══════════════════════════════════════ */

/* POST /anuncios/fotos — faz upload das fotos e retorna URLs */
app.post("/anuncios/fotos", auth, (req, res, next) => {
  uploadFotos.array("fotos", 10)(req, res, (err) => {
    if (err) {
      console.error('Erro multer fotos:', JSON.stringify(err));
      return res.status(500).json({ erro: 'Erro no upload: ' + (err.message || JSON.stringify(err)) });
    }
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ erro: 'Nenhum arquivo enviado' });
      }
      const fotos = req.files.map(f => ({ url: f.path, publicId: f.filename }));
      res.json({ fotos });
    } catch (err2) {
      console.error('Erro upload fotos:', JSON.stringify(err2));
      res.status(500).json({ erro: 'Erro ao processar fotos: ' + (err2.message || JSON.stringify(err2)) });
    }
  });
});

/* POST /anuncios/video — faz upload do vídeo e retorna URL */
app.post("/anuncios/video", auth, uploadVideos.single("video"), async (req, res) => {
  try {
    res.json({ video: { url: req.file.path, publicId: req.file.filename } });
  } catch (err) {
    console.error('Erro upload video:', err.message || err);
    res.status(500).json({ erro: 'Erro ao fazer upload do vídeo: ' + (err.message || 'erro desconhecido') });
  }
});

/* POST /anuncios — cria anúncio */
app.post("/anuncios", auth, async (req, res) => {
  try {
    const { titulo, descricao, preco, categoria, condicao, estado, cidade, fotos, video, whatsapp, detalhes } = req.body;

    if (!titulo || !descricao || !preco || !categoria || !estado || !cidade)
      return res.status(400).json({ erro: "Preencha todos os campos obrigatórios" });

    const anuncio = await Anuncio.create({
      titulo, descricao, preco, categoria, condicao,
      estado, cidade, fotos: fotos || [], video: video || null,
      whatsapp: whatsapp || "",
      detalhes: detalhes || {},
      usuario: req.userId,
    });

    await anuncio.populate("usuario", "nome fotoPerfil");
    res.status(201).json(anuncio);
  } catch (err) {
    res.status(500).json({ erro: "Erro ao criar anúncio" });
  }
});

/* GET /anuncios — lista com filtros */
app.get("/anuncios", async (req, res) => {
  try {
    const { categoria, estado, cidade, busca, pagina = 1, limite = 12, ordem = "recente" } = req.query;

    const filtro = { ativo: true };
    if (categoria) filtro.categoria = categoria;
    if (estado)    filtro.estado    = estado;
    if (cidade)    filtro.cidade    = cidade;
    if (busca)     filtro.$text     = { $search: busca };

    const sort = ordem === "menor-preco" ? { preco: 1 }
               : ordem === "maior-preco" ? { preco: -1 }
               : { criadoEm: -1 };

    const total    = await Anuncio.countDocuments(filtro);
    const anuncios = await Anuncio.find(filtro)
      .sort(sort)
      .skip((pagina - 1) * limite)
      .limit(Number(limite))
      .populate("usuario", "nome fotoPerfil telefone");

    res.json({
      anuncios,
      total,
      paginas: Math.ceil(total / limite),
      pagina:  Number(pagina),
    });
  } catch (err) {
    res.status(500).json({ erro: "Erro ao buscar anúncios" });
  }
});

/* GET /anuncios/destaques — para a homepage */
app.get("/anuncios/destaques", async (req, res) => {
  try {
    const anuncios = await Anuncio.find({ ativo: true })
      .sort({ views: -1, criadoEm: -1 })
      .limit(8)
      .populate("usuario", "nome fotoPerfil");
    res.json(anuncios);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar destaques" });
  }
});

/* GET /anuncios/:id — detalhe de um anúncio */
app.get("/anuncios/:id", async (req, res) => {
  try {
    const anuncio = await Anuncio.findById(req.params.id)
      .populate("usuario", "nome fotoPerfil telefone criadoEm");

    if (!anuncio) return res.status(404).json({ erro: "Anúncio não encontrado" });

    // Incrementa visualizações
    await Anuncio.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });

    res.json(anuncio);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar anúncio" });
  }
});

/* PUT /anuncios/:id — editar anúncio */
app.put("/anuncios/:id", auth, async (req, res) => {
  try {
    const anuncio = await Anuncio.findById(req.params.id);
    if (!anuncio) return res.status(404).json({ erro: "Anúncio não encontrado" });

    if (anuncio.usuario.toString() !== req.userId)
      return res.status(403).json({ erro: "Sem permissão para editar este anúncio" });

    const atualizado = await Anuncio.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(atualizado);
  } catch {
    res.status(500).json({ erro: "Erro ao editar anúncio" });
  }
});

/* DELETE /anuncios/:id — excluir anúncio */
app.delete("/anuncios/:id", auth, async (req, res) => {
  try {
    const anuncio = await Anuncio.findById(req.params.id);
    if (!anuncio) return res.status(404).json({ erro: "Anúncio não encontrado" });

    if (anuncio.usuario.toString() !== req.userId)
      return res.status(403).json({ erro: "Sem permissão para excluir este anúncio" });

    // Remove mídias do Cloudinary
    for (const foto of anuncio.fotos) {
      if (foto.publicId) await cloudinary.uploader.destroy(foto.publicId);
    }
    if (anuncio.video?.publicId) {
      await cloudinary.uploader.destroy(anuncio.video.publicId, { resource_type: "video" });
    }

    await Anuncio.findByIdAndDelete(req.params.id);
    res.json({ mensagem: "Anúncio excluído com sucesso" });
  } catch {
    res.status(500).json({ erro: "Erro ao excluir anúncio" });
  }
});

/* GET /usuarios/:id/anuncios — anúncios de um usuário */
app.get("/usuarios/:id/anuncios", async (req, res) => {
  try {
    const anuncios = await Anuncio.find({ usuario: req.params.id, ativo: true })
      .sort({ criadoEm: -1 });
    res.json(anuncios);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar anúncios do usuário" });
  }
});

/* ══════════════════════════════════════
   ROTAS — MENSAGENS / CHAT
══════════════════════════════════════ */

/* GET /mensagens/:anuncioId — histórico de uma conversa */
app.get("/mensagens/:anuncioId/:outroUserId", auth, async (req, res) => {
  try {
    const { anuncioId, outroUserId } = req.params;
    const ids = [req.userId, outroUserId].sort();
    const conversa = `${ids[0]}_${ids[1]}_${anuncioId}`;

    const msgs = await Mensagem.find({ conversa })
      .sort({ criadoEm: 1 })
      .populate("de", "nome fotoPerfil");

    // Marca como lidas
    await Mensagem.updateMany(
      { conversa, para: req.userId, lida: false },
      { lida: true }
    );

    res.json(msgs);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar mensagens" });
  }
});

/* GET /mensagens/conversas — lista de conversas do usuário */
app.get("/mensagens/conversas/lista", auth, async (req, res) => {
  try {
    // Busca última mensagem de cada conversa do usuário
    const conversas = await Mensagem.aggregate([
      { $match: { $or: [{ de: new mongoose.Types.ObjectId(req.userId) }, { para: new mongoose.Types.ObjectId(req.userId) }] } },
      { $sort: { criadoEm: -1 } },
      { $group: { _id: "$conversa", ultimaMensagem: { $first: "$$ROOT" } } },
      { $replaceRoot: { newRoot: "$ultimaMensagem" } },
      { $sort: { criadoEm: -1 } },
    ]);

    await Mensagem.populate(conversas, [
      { path: "de",     select: "nome fotoPerfil" },
      { path: "para",   select: "nome fotoPerfil" },
      { path: "anuncio", select: "titulo fotos" },
    ]);

    res.json(conversas);
  } catch {
    res.status(500).json({ erro: "Erro ao buscar conversas" });
  }
});

/* GET /mensagens/nao-lidas — contagem de não lidas */
app.get("/mensagens/nao-lidas", auth, async (req, res) => {
  try {
    const count = await Mensagem.countDocuments({ para: req.userId, lida: false });
    res.json({ naoLidas: count });
  } catch {
    res.status(500).json({ erro: "Erro ao contar mensagens" });
  }
});

/* ══════════════════════════════════════
   SOCKET.IO — CHAT EM TEMPO REAL
══════════════════════════════════════ */
const usuariosOnline = new Map(); // userId → socketId

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Token não fornecido"));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch {
    next(new Error("Token inválido"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.userId;
  usuariosOnline.set(userId, socket.id);
  console.log(`🟢 Usuário conectado: ${userId}`);

  // Notifica contatos que está online
  socket.broadcast.emit("usuario:online", { userId });

  /* ── Entrar numa conversa ── */
  socket.on("conversa:entrar", ({ outroUserId, anuncioId }) => {
    const ids     = [userId, outroUserId].sort();
    const sala    = `${ids[0]}_${ids[1]}_${anuncioId}`;
    socket.join(sala);
    socket.salaAtual = sala;
    console.log(`💬 ${userId} entrou na sala ${sala}`);
  });

  /* ── Enviar mensagem ── */
  socket.on("mensagem:enviar", async ({ para, anuncioId, texto }) => {
    try {
      if (!texto?.trim()) return;

      const ids     = [userId, para].sort();
      const conversa = `${ids[0]}_${ids[1]}_${anuncioId}`;

      // Salva no banco
      const msg = await Mensagem.create({
        conversa,
        de:     userId,
        para,
        anuncio: anuncioId || null,
        texto:  texto.trim(),
      });

      await msg.populate("de", "nome fotoPerfil");

      // Envia para a sala (os dois usuários recebem)
      io.to(conversa).emit("mensagem:nova", msg);

      // Se o destinatário não está na sala, manda notificação
      const socketDest = usuariosOnline.get(para);
      if (socketDest) {
        const socketObj = io.sockets.sockets.get(socketDest);
        if (!socketObj?.rooms.has(conversa)) {
          io.to(socketDest).emit("notificacao:mensagem", {
            de:      msg.de,
            anuncio: anuncioId,
            texto:   texto.trim(),
          });
        }
      }
    } catch (err) {
      socket.emit("erro", { mensagem: "Erro ao enviar mensagem" });
    }
  });

  /* ── Digitando ── */
  socket.on("digitando:inicio", ({ sala }) => {
    socket.to(sala).emit("digitando:inicio", { userId });
  });
  socket.on("digitando:fim", ({ sala }) => {
    socket.to(sala).emit("digitando:fim", { userId });
  });

  /* ── Desconexão ── */
  socket.on("disconnect", () => {
    usuariosOnline.delete(userId);
    socket.broadcast.emit("usuario:offline", { userId });
    console.log(`🔴 Usuário desconectado: ${userId}`);
  });
});


/* ══════════════════════════════════════
   ROTA — IA (Claude) — Gerar descrição
══════════════════════════════════════ */
app.post('/ia/descricao', async (req, res) => {
  try {
    const { titulo, categoria, preco, condicao, cidade, estado, detalhes } = req.body;

    const detalhesTexto = detalhes
      ? Object.entries(detalhes).map(([k,v]) => `${k}: ${v}`).join(', ')
      : '';

    const prompt = `Você é um especialista em copywriting para marketplaces brasileiros como OLX e Mercado Livre.

Gere uma descrição de anúncio profissional, persuasiva e natural em português brasileiro para o seguinte produto:

- Título: ${titulo || 'não informado'}
- Categoria: ${categoria || 'não informada'}
- Preço: ${preco || 'não informado'}
- Condição: ${condicao || 'não informada'}
- Localização: ${cidade ? cidade + ' - ' + estado : 'não informada'}
${detalhesTexto ? `- Detalhes: ${detalhesTexto}` : ''}

Escreva uma descrição de 3 a 5 parágrafos curtos que:
1. Destaque os principais benefícios e características do produto
2. Seja honesta e direta
3. Inclua uma chamada para ação no final
4. Use linguagem natural e brasileira
5. Tenha no máximo 400 palavras

Retorne APENAS a descrição, sem título, sem prefácio, sem comentários.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    const data = await response.json();
    const texto = data.content?.[0]?.text?.trim();

    if (!texto) return res.status(500).json({ erro: 'Não foi possível gerar a descrição' });
    res.json({ descricao: texto });

  } catch (err) {
    res.status(500).json({ erro: 'Erro ao conectar com a IA' });
  }
});

/* ══════════════════════════════════════
   HEALTH CHECK
══════════════════════════════════════ */
app.get("/", (req, res) => {
  res.json({
    status:  "online",
    versao:  "1.0.0",
    banco:   mongoose.connection.readyState === 1 ? "conectado" : "desconectado",
  });
});

/* ══════════════════════════════════════
   START
══════════════════════════════════════ */
httpServer.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
