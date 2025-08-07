// server.js

// 1. IMPORTAÇÃO DOS PACOTES
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // Driver do PostgreSQL
const bcrypt = require('bcrypt'); // Para hashear senhas
const jwt = require('jsonwebtoken'); // Para criar tokens de sessão

// 2. CONFIGURAÇÃO INICIAL
const app = express();
const port = 3000; // O backend rodará na porta 3000
const jwtSecret = 'seu_segredo_super_secreto_para_jwt'; // Mude isso para uma string aleatória e segura

// Middlewares para o Express
app.use(cors()); // Habilita o CORS para todas as rotas
app.use(express.json()); // Permite que o servidor entenda requisições com corpo em JSON

// 3. CONFIGURAÇÃO DA CONEXÃO COM O BANCO DE DADOS
// Altere os dados abaixo para corresponder à sua configuração do PostgreSQL
const pool = new Pool({
    user: 'sigshow_user',
    host: 'localhost',
    database: 'sigshow_db', // Mantenha o nome da sua base de dados
    password: 'admin',      // A sua senha
    port: 5432,
});

// 4. DEFINIÇÃO DAS ROTAS (ENDPOINTS)

// Rota de teste para verificar se o servidor está no ar
app.get('/', (req, res) => {
    res.send('Servidor do SigShow está funcionando!');
});

/**
 * ROTA DE LOGIN
 * Recebe 'nome' e 'senha' no corpo da requisição.
 * Verifica primeiro na tabela 'admin', depois em 'organizador'.
 */
app.post('/login', async (req, res) => {
    const { nome, senha } = req.body;

    if (!nome || !senha) {
        return res.status(400).json({ message: 'Nome de usuário e senha são obrigatórios.' });
    }

    try {
        // Tenta encontrar o usuário como admin
        let userResult = await pool.query('SELECT * FROM admin WHERE nome = $1', [nome]);
        let userType = 'admin';

        // Se não for admin, tenta encontrar como organizador
        if (userResult.rows.length === 0) {
            userResult = await pool.query('SELECT * FROM organizador WHERE nome = $1', [nome]);
            userType = 'organizador';
        }

        // Se não encontrou em nenhuma tabela
        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Usuário não encontrado.' });
        }

        const user = userResult.rows[0];

        // Compara a senha enviada com a senha hasheada no banco
        const isPasswordValid = await bcrypt.compare(senha, user.senha);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Senha inválida.' });
        }

        // Se a senha for válida, gera um token JWT
        const tokenPayload = {
            id: user.id_admin || user.id_organizador,
            nome: user.nome,
            type: userType
        };

        const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '1h' }); // Token expira em 1 hora

        // Envia o token e os dados do usuário como resposta
        res.status(200).json({
            message: 'Login bem-sucedido!',
            token: token,
            user: tokenPayload
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// Rota de exemplo para registrar um novo organizador com senha hasheada
// Em uma aplicação real, você teria mais validações aqui.
app.post('/register/organizador', async (req, res) => {
    const { nome, senha, nome_empresa } = req.body;

    if (!nome || !senha || !nome_empresa) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    try {
        // Gera o "hash" da senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(senha, saltRounds);

        const newUser = await pool.query(
            'INSERT INTO organizador (nome, senha, nome_empresa) VALUES ($1, $2, $3) RETURNING *',
            [nome, hashedPassword, nome_empresa]
        );

        res.status(201).json({
            message: 'Organizador registrado com sucesso!',
            user: newUser.rows[0]
        });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ message: 'Erro ao registrar usuário. O nome já pode existir.' });
    }
});


// 5. INICIALIZAÇÃO DO SERVIDOR
app.listen(port, () => {
    console.log(`Servidor do SigShow rodando em http://localhost:${port}`);
});
