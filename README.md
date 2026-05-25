# 🏙️ Ayda - Sistema de Relatos Urbanos

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-003545?style=for-the-badge&logo=mariadb&logoColor=white)

## 📌 Sobre o Projeto

O **Ayda** é um sistema web desenvolvido como projeto acadêmico para o **Projeto Integrador do 3º semestre da UNIVAG**.

A proposta do projeto é facilitar o registro e a visualização de problemas urbanos, permitindo que cidadãos publiquem relatos com imagem, descrição e localização. A aplicação foi pensada para tornar a comunicação de problemas da cidade mais simples, visual e acessível.

Entre os exemplos de problemas que podem ser relatados estão buracos em vias públicas, postes quebrados, vazamentos de água, descarte irregular de lixo e outras situações que afetam o espaço urbano.

---

## 🎯 Objetivo

O objetivo principal do **Ayda** é oferecer uma plataforma onde os usuários possam registrar problemas encontrados em espaços públicos de forma prática.

Além disso, o projeto também teve como objetivo aplicar conceitos de desenvolvimento web full stack, integrando front-end, back-end, banco de dados, upload de arquivos e autenticação de usuários.

---

## ✨ Funcionalidades

- Cadastro de usuários
- Login com e-mail ou nome de usuário
- Autenticação com Google
- Publicação de relatos urbanos
- Envio de imagem junto ao relato
- Opção de publicar como anônimo
- Campo de localização do problema
- Captura de imagem pela câmera
- Troca de câmera em dispositivos compatíveis
- Listagem dos relatos cadastrados
- Exibição da imagem, nome, descrição, localização e data do relato
- Exclusão de relatos cadastrados
- Interface visual voltada para problemas urbanos
- Layout responsivo para diferentes tamanhos de tela

---

## 🛠️ Tecnologias Utilizadas

### Front-end

- **HTML5**  
  Utilizado para estruturar as páginas, formulários, botões, seções e elementos visuais do sistema.

- **CSS3**  
  Utilizado para estilização da interface, responsividade, organização visual dos relatos, botões, telas e componentes.

- **JavaScript**  
  Utilizado para adicionar interatividade no front-end, controlar eventos, manipular formulários, capturar imagens e comunicar com o back-end.

---

### Back-end

- **Node.js**  
  Utilizado para executar o servidor da aplicação.

- **Express**  
  Framework utilizado para criação das rotas da API e gerenciamento das requisições HTTP.

- **MariaDB**  
  Banco de dados utilizado para armazenar usuários, relatos, imagens, localização e data de criação.

- **Multer**  
  Utilizado para processar o upload de imagens enviadas pelo usuário.

- **Bcrypt**  
  Utilizado para criptografar senhas dos usuários antes de salvar no banco de dados.

- **CORS**  
  Utilizado para permitir a comunicação entre front-end e back-end.

- **Google Auth Library**  
  Utilizada para autenticação com conta Google.

---

## 📁 Estrutura do Projeto

```bash
TrabalhoUnivagAyda/
├── fonte/
│   └── sf-pro-display/
├── imagens/
│   └── imagens utilizadas na interface
├── uploads/
│   └── arquivos enviados pelo usuário
├── index.html
├── index.css
├── main.html
├── main.css
├── como-usar.html
├── como-usar.css
├── server.js
├── package.json
├── package-lock.json
├── .env
├── .gitignore
├── LICENSE
└── README.md
