const Sequelize = require('sequelize')
const sequelize = require('../database/db')
const crypto = require('crypto')

const User = sequelize.define('user', {
    id: {
      type: Sequelize.STRING,
      allowNull: false,
      primaryKey: true,
    },
    name: {
      type: Sequelize.STRING(255),
      allowNull: false,
    },
    email: {
      type: Sequelize.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    salt: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    cpf: {
      type: Sequelize.STRING,
      allowNull: false,
      unique: true,
    },
    resetToken: {
      type: Sequelize.STRING,
    },
    resetTokenExpiration: {
      type: Sequelize.DATE,
    },
    resetPasswordAttempts: {
      type: Sequelize.INTEGER,
      },
  });
  
  module.exports = User