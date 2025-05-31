// Captura erros globais para não deixar o processo morrer silenciosamente
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // opcional: process.exit(1); // para reiniciar o processo (depende da sua estratégia)
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  // opcional: process.exit(1);
});

require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { OAuth2Client } = require("google-auth-library");
const mariadb = require("mariadb");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
if (!CLIENT_ID) {
  console.warn("⚠️ GOOGLE_CLIENT_ID não definido no .env");
}
const googleClient = new OAuth2Client(CLIENT_ID);

// Middlewares
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static("public"));

const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } }); // 5 MB

// Pools MariaDB
const authPool = mariadb.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  connectionLimit: 10
});

const pool = mariadb.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  connectionLimit: 5
});

// Função para verificar se a conexão está ok
async function testarConexao() {
  try {
    const conn = await pool.getConnection();
    conn.release();
    console.log("Conexão ao banco MariaDB OK.");
  } catch (err) {
    console.error("Erro na conexão com o banco:", err);
  }
}
testarConexao();

// Cria tabelas se não existirem
async function criarTabelaUsuarios() {
  let conn;
  try {
    conn = await authPool.getConnection();
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
    console.log("Tabela usuarios verificada/criada.");
  } catch (err) {
    console.error("Erro ao criar tabela usuarios:", err);
  } finally {
    if (conn) conn.release();
  }
}
criarTabelaUsuarios();

async function criarTabelaImagens() {
  let conn;
  try {
    conn = await pool.getConnection();
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
    console.log("Tabela imagens verificada/criada.");
  } catch (err) {
    console.error("Erro ao criar tabela imagens:", err);
  } finally {
    if (conn) conn.release();
  }
}
criarTabelaImagens();

// Cria tabela "imagens" se não existir
async function criarTabelaImagens() {
  let conn;
  try {
    conn = await pool.getConnection();
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
  } catch (err) {
    console.error("Erro ao criar tabela imagens:", err);
  } finally {
    if (conn) conn.release();
  }
}
criarTabelaImagens();

// Registro de usuário
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
    if (err.code === "ER_DUP_ENTRY") {
      res.status(409).send("Nome de usuário ou e-mail já estão em uso.");
    } else {
      res.status(500).send("Erro interno ao cadastrar usuário.");
    }
  }
});

// Login por email ou nome de usuário
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
    res.send({ message: "Login bem-sucedido", id: user.id });
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).send("Erro no login.");
  }
});

// Autenticação com Google
app.post("/auth/google", async (req, res) => {
  const { token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID
    });
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

// Upload de imagem com localização
app.post("/upload", upload.single("imagem"), async (req, res) => {
  const { nome, relato, localizacao } = req.body;
  const imagem = req.file?.buffer;
  if (!imagem) return res.status(400).send("Nenhuma imagem enviada.");
  if (!localizacao) return res.status(400).send("Campo 'localizacao' é obrigatório.");

  let conn;
  try {
    conn = await pool.getConnection();
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

// Busca pessoas (imagens)
app.get("/pessoas", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
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

// Excluir pessoa (imagem)
app.delete("/excluir/:id", async (req, res) => {
  const { id } = req.params;
  let conn;
  try {
    conn = await pool.getConnection();
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
  res.sendFile(path.join(__dirname, "ProjetoIntegradorIII", "main.html"));
});

// Atenção: ouvir em 0.0.0.0 para funcionar no Railway
app.listen(port, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${port}`);
});
