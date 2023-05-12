require('dotenv').config();

const Sequelize = require('sequelize') //importando o Sequelize

const sequelize = new Sequelize('railway', 'root', process.env.DB_PASSWORD, {
    host: 'containers-us-west-210.railway.app',
    dialect: 'mysql',
    port: 6018
})

module.exports = sequelize