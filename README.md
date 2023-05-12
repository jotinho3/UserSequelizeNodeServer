# Meu projeto para alunos da Gama Acadedmy de Backend Desafio3

Este é um projeto que demonstra um sistema de autenticação e gerenciamento de usuários utilizando Node.js, Express, Sequelize, JWT e criptografia de senhas.

## Funcionalidades

- Registro de usuário com senha criptografada
- Login de usuário com verificação de senha
- Geração de token JWT para autenticação
- Rotas protegidas que exigem autenticação

## Requisitos

- Node.js
- Banco de dados MySQL
- Variáveis de ambiente configuradas (consulte o arquivo `.env.example`)

## Instalação

1. Clone o repositório:

   ```bash
   git clone https://github.com/seu-usuario/meu-projeto.git

Instale as dependências:

bash

cd meu-projeto
npm install

Configure as variáveis de ambiente:

Renomeie o arquivo .env.example para .env
Edite o arquivo .env e defina os valores apropriados para as variáveis de ambiente
Execute as migrações do banco de dados caso ja tenha um:

bash

npm run migrate

Inicie o servidor:

bash

npm start

Uso
Para registrar um novo usuário, faça uma requisição POST para /register com os campos name, email e password.
Para fazer login, faça uma requisição POST para /login com os campos email e password.
A rota /users/:id retorna os detalhes de um usuário específico (requer autenticação).
A rota /users retorna todos os usuários (requer autenticação).
Contribuição
Contribuições são bem-vindas! Se você tiver sugestões, melhorias ou correções, sinta-se à vontade para enviar um pull request.
