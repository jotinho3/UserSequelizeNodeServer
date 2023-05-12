const User = require('../models/User')

const verifyUserId = async (req, res, next) => {
    const { id } = req.params; //Aqui o id que o usuário colocar vira para o params da requisição

    try {
        const user = await User.findByPk(id) // Aqui eu vou pegar o id que o usuário colocou e vou checar se ele bate com o DB
        
        if (!user) {
            return res.status(400).json({message: 'Usuário/ID não encontrado!'})
        }

        req.user = user // Atrelando o usuário a request da rota, e assim ele estara salvo para consumir
        // res.status(200).json({message: 'Usuário encontrado!', id})
        next()
    } 
    catch (error) {
        console.log('Não foi possível verificar o ID', error)
        res.status(500).json({ message: 'Não foi possível verificar o ID'})
        
    }

}

module.exports = verifyUserId