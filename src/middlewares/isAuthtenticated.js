const jwt = require('jsonwebtoken'); // Biblioteca para criação e verificação de tokens JWT
require('dotenv').config(); // Carrega as variáveis de ambiente definidas no arquivo .env

const isAuthenticated = async (req, res, next) => {
  const authHeader = req.headers['authorization']; // Obtém o valor do cabeçalho 'Authorization' da requisição

  if (!authHeader) {
    return res.status(401).json({ message: 'Cabeçalho de autorização ausente' });
  }

  const token = authHeader.split(' ')[1]; // Separa o valor do token do prefixo 'Bearer'

  if (!token) {
    return res.status(401).json({ message: 'Token ausente' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verifica a validade e decodifica o token usando a chave secreta definida no arquivo .env
    req.user = decoded; // Define o objeto 'user' no objeto 'req' para uso posterior nas rotas
    next(); // Chama a próxima função/middleware na cadeia de middleware
  } catch (err) {
    console.error(err);
    return res.status(403).json({ message: 'Token inválido' });
  }
};

module.exports = isAuthenticated;
