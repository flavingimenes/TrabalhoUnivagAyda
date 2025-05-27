// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcrypt");
const { OAuth2Client } = require("google-auth-library");
const mariadb = require("mariadb");
const path = require("path");

const app = express();
const port = 3000;
const CLIENT_ID = "760527345403-gvthlq5bnv4aqh58uhnksn5inmbis5vr.apps.googleusercontent.com";
const googleClient = new OAuth2Client(CLIENT_ID);

// Middlewares
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static("public"));
const upload = multer();

// Pool MariaDB para auth (banco 'seu_banco')
const authPool = mariadb.createPool({
  host: "localhost",
  user: "root",
  password: "root",
  database: "seu_banco",
  connectionLimit: 10
});

// Pool MariaDB para imagens (banco 'teste')
const mariaPool = mariadb.createPool({
  host: "localhost",
  user: "root",
  password: "root",
  database: "teste",
  connectionLimit: 5
});

// Cria tabela usuarios (se não existir)
async function criarTabelaUsuarios() {
  const conn = await authPool.getConnection();
  await conn.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nome VARCHAR(255) UNIQUE,
      email VARCHAR(255) UNIQUE,
      senha VARCHAR(255),
      foto TEXT,
      criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  conn.release();
}
criarTabelaUsuarios();

// Cria tabela imagens (se não existir), incluindo coluna localizacao
async function criarTabelaImagens() {
  const conn = await mariaPool.getConnection();
  await conn.query(`
    CREATE TABLE IF NOT EXISTS imagens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      relato TEXT NOT NULL,
      localizacao VARCHAR(255) NOT NULL,
      imagem LONGBLOB NOT NULL,
      criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  conn.release();
}
criarTabelaImagens();

// Registro de usuário (manual)
app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).send("Nome de usuário, email e senha são obrigatórios.");
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const conn = await authPool.getConnection();
    await conn.query(
      "INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)",
      [username, email, hash]
    );
    conn.release();
    res.status(201).send("Cadastro realizado com sucesso.");
  } catch (err) {
    console.error("Erro ao cadastrar usuário:", err);
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(409).send("Nome de usuário ou e-mail já estão em uso.");
    } else {
      res.status(500).send("Erro interno ao cadastrar usuário.");
    }
  }
});

// Login por e-mail ou nome de usuário
app.post("/auth/login", async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).send("Identificador e senha são obrigatórios.");
  }
  try {
    const conn = await authPool.getConnection();
    const rows = await conn.query(
      "SELECT id, senha FROM usuarios WHERE email = ? OR nome = ?",
      [identifier, identifier]
    );
    conn.release();
    if (rows.length === 0) {
      return res.status(401).send("Usuário não encontrado.");
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.senha);
    if (!match) {
      return res.status(401).send("Senha incorreta.");
    }
    res.send("Login bem-sucedido.");
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).send("Erro no login.");
  }
});

// Autenticação com Google
app.post("/auth/google", async (req, res) => {
  const { token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: token, audience: CLIENT_ID });
    const payload = ticket.getPayload();
    const { name, email, picture } = payload;
    const conn = await authPool.getConnection();
    const rows = await conn.query("SELECT id FROM usuarios WHERE email = ?", [email]);
    if (rows.length === 0) {
      await conn.query(
        "INSERT INTO usuarios (nome, email, foto) VALUES (?, ?, ?)",
        [name, email, picture]
      );
    }
    conn.release();
    res.send(`Bem-vindo, ${name}!`);
  } catch (err) {
    console.error("Erro ao autenticar Google:", err);
    res.status(401).send("Token inválido ou expirado.");
  }
});

// Upload de imagem com localizacao
app.post("/upload", upload.single("imagem"), async (req, res) => {
  const { nome, relato, localizacao } = req.body;
  const imagem = req.file?.buffer;
  if (!imagem) {
    return res.status(400).send("Nenhuma imagem enviada.");
  }
  if (!localizacao) {
    return res.status(400).send("Campo 'localizacao' é obrigatório.");
  }
  let conn;
  try {
    conn = await mariaPool.getConnection();
    await conn.query(
      "INSERT INTO imagens (nome, relato, localizacao, imagem) VALUES (?, ?, ?, ?)",
      [nome, relato, localizacao, imagem]
    );
    res.send("Imagem e dados enviados com sucesso!");
  } catch (err) {
    console.error("Erro ao inserir no banco:", err);
    res.status(500).send("Erro ao inserir no banco.");
  } finally {
    if (conn) conn.release();
  }
});

// Busca pessoas com localizacao e criado_em
app.get("/pessoas", async (req, res) => {
  let conn;
  try {
    conn = await mariaPool.getConnection();
    const rows = await conn.query(`
      SELECT 
        id, 
        nome, 
        relato, 
        localizacao, 
        TO_BASE64(imagem) AS imagem,
        criado_em
      FROM imagens
      ORDER BY criado_em DESC
    `);

    const resultado = rows.map(r => ({
      id: r.id,
      nome: r.nome,
      relato: r.relato,
      localizacao: r.localizacao,
      imagem: r.imagem,
      criado_em: r.criado_em
    }));

    res.json(resultado);
  } catch (err) {
    console.error("Erro ao buscar dados:", err);
    res.status(500).send("Erro ao buscar dados.");
  } finally {
    if (conn) conn.release();
  }
});

// Excluir pessoa
app.delete("/excluir/:id", async (req, res) => {
  const { id } = req.params;
  let conn;
  try {
    conn = await mariaPool.getConnection();
    const result = await conn.query("DELETE FROM imagens WHERE id = ?", [id]);
    if (result.affectedRows > 0) {
      res.send("Cadastro excluído com sucesso!");
    } else {
      res.status(404).send("Cadastro não encontrado.");
    }
  } catch (err) {
    console.error("Erro ao excluir o cadastro:", err);
    res.status(500).send("Erro ao excluir o cadastro.");
  } finally {
    if (conn) conn.release();
  }
});

// Fallback para main.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
