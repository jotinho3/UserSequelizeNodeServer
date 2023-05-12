const express = require("express"); // Importa o módulo Express
const app = express(); // Atribui as funcionalidades do Express à variável 'app'
const port = 3000; // Define a porta em que o servidor será executado
const sequelize = require("./database/db"); // Importa o módulo Sequelize para conexão com o banco de dados
const User = require("../src/models/User"); // Importa o modelo de dados do usuário
const bodyParser = require("body-parser"); // Importa o módulo Body Parser para tratar as requisições HTTP
const { v4: uuidv4 } = require("uuid"); // Importa o módulo UUID para gerar IDs únicos
const Joi = require('joi'); // Importa o módulo Joi para validação de dados

const cookie = require('cookie'); // Importa o módulo Cookie para trabalhar com cookies

// Middlewares
const verifyUserId = require("./middlewares/VerifyId"); // Importa o middleware de verificação de ID do usuário
const requireLogin = require("./middlewares/requireLogin"); // Importa o middleware de autenticação de login do usuário

const crypto = require("crypto"); // Importa o módulo Crypto para criptografia
const jwt = require("jsonwebtoken"); // Importa o módulo JSON Web Token para geração de tokens
const nodemailer = require("nodemailer"); // Importa o módulo Nodemailer para envio de emails

const cors = require('cors'); // Importa o módulo CORS para lidar com requisições de diferentes origens
const session = require('express-session'); // Importa o módulo Express Session para gerenciamento de sessões
const isAuthenticated = require("./middlewares/isAuthtenticated"); // Importa o middleware de autenticação de sessão do usuário

const cookieParser = require('cookie-parser'); // Importa o módulo Cookie Parser para trabalhar com cookies no Express
app.use(cookieParser()); // Usa o Cookie Parser como middleware no Express

const SECRET_KEY = process.env.SECRET_KEY  // Define a chave secreta para assinatura dos tokens JWT, lembrando que está sendo pega do arquivo .env file 


require('dotenv').config();


app.use(session({
  secret: SECRET_KEY,
  resave: false,
  saveUninitialized: false
}));

app.use(cors());




sequelize
  .sync()
  .then(() => {
    console.log("Sincronizado com o banco de dados");
  })
  .catch((error) => {
    console.log("Sincronização não sucedida");
  });

app.use(bodyParser.json()); // middleware bodyParser, vai ser executado em todas as rotas abaixo dele entre a req e a res

app.post('/signup', async (req, res) => {
  const { name, email, password, cpf } = req.body;

  // Valida o email
  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ message: 'Email inválido!' });
  }

  // Valida a senha
  if (!password || password.length < 8) {
    return res.status(400).json({ message: 'A senha deve ter pelo menos 8 caracteres' });
  }

  // Valida o CPF
  if (!cpf || !/\d{3}\.\d{3}\.\d{3}-\d{2}/.test(cpf)) {
    return res.status(400).json({ message: 'CPF inválido' });
  }

  // Gera um salt único para a criptografia da senha
  const salt = crypto.randomBytes(16).toString('hex');

  // Cria o hash da senha usando o salt
  const passwordHash = crypto
    .createHash('sha256')
    .update(password + salt)
    .digest('hex');

  try {
    // Cria o usuário no banco de dados
    const user = await User.create({
      id: uuidv4(),
      name,
      email,
      password: passwordHash,
      salt, //é necessário armazenar o valor de salt na tabela de usuario, assim como criar esse campo salt no Model do User
      cpf,
    });

    res.status(200).json({ message: 'Usuário criado com sucesso!', user });
  } catch (error) {
    console.log('Não foi possível criar o usuário', error);
    res.status(500).json({ message: 'Não foi possível criar o usuário' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Procura o usuário pelo email no banco de dados
  const user = await User.findOne({ where: { email } });

  if (!user) {
    return res.status(401).json({ message: 'Email ou senha inválidos' });
  }

  // Gera o hash da senha informada usando o salt armazenado no usuário
  const passwordHash = crypto
    .createHash('sha256')
    .update(password + user.salt)
    .digest('hex');

  // Verifica se o hash da senha corresponde ao hash armazenado no usuário
  if (passwordHash !== user.password) {
    return res.status(401).json({ message: 'Email ou senha inválidos' });
  }

  // Gera um token JWT
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);

  res.json({ token });
});











  
app.get('/session', requireLogin, async (req, res) => {
  const userId = req.user.id; // Obtém o ID do usuário autenticado fornecido pelo middleware requireLogin
  if (userId) {
    // Procura o usuário no banco de dados com base no ID obtido
    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET); // Gera um token JWT com o ID do usuário
    req.session.token = token; // Define o token JWT na sessão do usuário
    res.status(200).json({ userId });
  } else {
    res.status(401).json({ error: 'Não autorizado' });
  }
});

app.get('/users/:id', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params; // Obtém o parâmetro "id" da requisição, fornecido pelo JWT autenticado no middleware isAuthenticated
    const user = await User.findByPk(id); // Procura o usuário no banco de dados com base no ID fornecido
    if (!user) {
      return res.sendStatus(404); // Retorna status 404 se o usuário não for encontrado
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
    }); // Retorna os detalhes do usuário encontrado
  } catch (error) {
    console.error(error);
    res.sendStatus(500); // Retorna status 500 se ocorrer algum erro durante a busca do usuário
  }
});

app.get('/users', async (req, res) => {
  const users = await User.findAll(); // Busca todos os usuários no banco de dados

  // const users = await User.findAll({where: {
  //     name: 'Joao Pedro Marques'
  // }});

  console.log(users); // Exibe os usuários no console

  res.status(200).json({ users }); // Retorna os usuários encontrados como resposta
});


app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const { error } = validateEmail(req.body.email);

  // Função para validar o formato do email usando Joi
  function validateEmail(email) {
    const schema = Joi.object({
      email: Joi.string().email().required(),
    });
  
    return schema.validate({ email });
  }

  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    // Encontra o usuário com base no email fornecido
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res
        .status(404)
        .json({ message: "Email não encontrado em nosso banco de dados!" });
    }

    // Verifica se o usuário excedeu o número máximo de tentativas de redefinição de senha
    if (user.resetPasswordAttempts >= 5) {
      return res
        .status(429)
        .json({ message: "Muitas tentativas de redefinição de senha. Por favor, tente novamente mais tarde." });
    }

    // Gera um token de redefinição de senha
    const resetToken = crypto.randomBytes(2).toString("hex"); // Gera um valor aleatório
    const resetTokenExpiration = Date.now() + 3600000; // Define uma data de expiração

    // Incrementa o número de tentativas de redefinição de senha para o usuário
    await user.update({ resetPasswordAttempts: user.resetPasswordAttempts + 1 });

    // Atualiza o registro do usuário com o token de redefinição e a data de expiração
    await user.update({ resetToken, resetTokenExpiration });

    // Gera um token JWT contendo o ID do usuário e o token de redefinição
    const token = jwt.sign({ id: user.id, resetToken }, process.env.JWT_SECRET);

    // Configuração do transporte de e-mail usando nodemailer
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "jotajotinho3@gmail.com",
        pass: `${process.env.NODEMAILER_PASSWORD}`,
      },
    });

    const mailData = {
      // Cria o e-mail
      from: `${process.env.NODEMAILER_EMAIL_SENDER}`,
      to: user.email,
      subject: "Email de redefinição de senha",
      html: `
                <p>Olá ${user.name},</p>
                <p>Recebemos uma solicitação para redefinir sua senha!</p>
                <p>Por favor, copie o seguinte token para redefinir sua senha:</p>
                <p>${resetToken}</p> 
                <p>Este token expirará em 1 hora</p>
                <p>Obrigado!</p>
            `,
    };

    await transporter.sendMail(mailData); // Envio do e-mail!

    res
      .status(200)
      .json({
        message: "Password reset email has been sent successfully!",
      });
  } catch (error) {
    console.log(
      "Unable to send password reset email",
      error
    );
    res
      .status(500)
      .json({
        message: "Unable to send password reset email",
      });
  }
});






app.post("/reset-password", async (req, res) => {
  const { newPassword, resetToken } = req.body;


  try {
  
    const user = await User.findOne({ where: { resetToken: resetToken } });

    if (!user) {
      return res
        .status(404)
        .json({ message: "Email não encontrado no nosso banco de dados!" });
    }

    if (user.resetTokenExpiration < Date.now()) {
      return res.status(400).json({ message: "Token expirado" });
    }

    // Update the forgotten password
    const passwordHash = crypto
      .createHash('sha256')
      .update(newPassword + user.salt)
      .digest('hex');
  
    await user.update({
      password: passwordHash,
      resetToken: null,
      resetTokenExpiration: null,
    });

    res.status(200).json({ message: "Senha trocada com sucesso!" });
  } catch (error) {
    console.log("Não foi possível trocar a senha!", error);
    res.status(500).json({ message: "Não foi possível trocar a senha!" });
  }
});


app.listen(port, () => {
  console.log(`Server online em ${port}`);
});
