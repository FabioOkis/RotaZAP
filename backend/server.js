require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Configurações Globais
app.use(cors());
app.use(express.json());

// --- MIDDLEWARES ---

// Middleware para verificar o token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    req.user = user;
    next();
  });
};

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Verificar se já existe
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'E-mail já está em uso.' });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar o usuário
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword
      }
    });

    res.status(201).json({ message: 'Usuário criado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuário
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Credenciais inválidas.' });
    }

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciais inválidas.' });
    }

    // Gerar token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, name: user.name });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// --- ROTAS DE LIMITES E ROTAS ---

app.post('/api/routes/add', authenticateToken, async (req, res) => {
  try {
    const { numberOfRoutesToAdd } = req.body;
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0]; // Formato YYYY-MM-DD

    // Verificar se tem assinatura ativa
    const subscription = await prisma.subscription.findUnique({ where: { userId } });
    const isActive = subscription && subscription.status === 'active' && subscription.expiresAt > new Date();

    if (isActive) {
      // Tem plano, rotas ilimitadas. Pode adicionar sem checar limites.
      return res.json({ allowed: true, message: 'Rotas adicionadas (plano premium)' });
    }

    // Se não tem plano ativo, verificar limite gratuito diário (10)
    let usage = await prisma.routeDailyUsage.findUnique({
      where: { userId_date: { userId, date: today } }
    });

    if (!usage) {
      // Cria o registro do dia
      usage = await prisma.routeDailyUsage.create({
        data: { userId, date: today, count: 0 }
      });
    }

    if (usage.count + numberOfRoutesToAdd > 10) {
      return res.status(403).json({ 
        allowed: false, 
        error: 'Limite diário de 10 rotas excedido.',
        currentUsage: usage.count,
        limit: 10
      });
    }

    // Incrementa a contagem de rotas
    await prisma.routeDailyUsage.update({
      where: { id: usage.id },
      data: { count: usage.count + numberOfRoutesToAdd }
    });

    res.json({ allowed: true, currentUsage: usage.count + numberOfRoutesToAdd });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao verificar limites.' });
  }
});

// Endpoint para apenas checar o status atual (mostrar no painel)
app.get('/api/routes/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];

    const subscription = await prisma.subscription.findUnique({ where: { userId } });
    const isActive = subscription && subscription.status === 'active' && subscription.expiresAt > new Date();

    const usage = await prisma.routeDailyUsage.findUnique({
      where: { userId_date: { userId, date: today } }
    });

    res.json({
      isPremium: isActive,
      plan: subscription?.plan || 'free',
      dailyUsage: usage ? usage.count : 0,
      limit: 10
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar status' });
  }
});

// --- ROTAS DO MERCADO PAGO ---

app.post('/api/payments/pix', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body; // 'diario', 'mensal', 'trimestral'
    const userId = req.user.id;

    // Configurar valores
    let amount = 0;
    let days = 0;

    if (plan === 'diario') { amount = 1.00; days = 1; }
    else if (plan === 'mensal') { amount = 20.00; days = 30; }
    else if (plan === 'trimestral') { amount = 50.00; days = 90; }
    else { return res.status(400).json({ error: 'Plano inválido' }); }

    // Chamada direta para a API do Mercado Pago usando fetch para criar PIX
    const response = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Idempotency-Key': `${userId}-${Date.now()}` // Previne pagamentos duplicados acidentais
      },
      body: JSON.stringify({
        transaction_amount: amount,
        description: `RotaZAP - Plano ${plan}`,
        payment_method_id: "pix",
        payer: {
          email: req.user.email
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Erro Mercado Pago:', data);
      return res.status(500).json({ error: 'Falha ao comunicar com o banco.' });
    }

    // Salvar no banco a "intenção" de pagamento para este usuário
    await prisma.subscription.upsert({
      where: { userId },
      update: {
        status: 'pending',
        plan: plan,
        mpPreferenceId: data.id.toString()
      },
      create: {
        userId,
        status: 'pending',
        plan: plan,
        mpPreferenceId: data.id.toString()
      }
    });

    // Retorna os dados do PIX (QR Code e Copia/Cola) para o frontend exibir
    res.json({
      paymentId: data.id,
      qr_code: data.point_of_interaction.transaction_data.qr_code,
      qr_code_base64: data.point_of_interaction.transaction_data.qr_code_base64
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno ao gerar PIX.' });
  }
});

// Polling do Frontend: Verifica se o pagamento já foi aprovado
app.get('/api/payments/status/:paymentId', authenticateToken, async (req, res) => {
  try {
    const { paymentId } = req.params;
    const userId = req.user.id;

    // Consultar o pagamento na API do MP
    const response = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
      headers: {
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`
      }
    });

    const data = await response.json();

    if (data.status === 'approved') {
      // Atualizar o banco liberando a conta do entregador
      const sub = await prisma.subscription.findUnique({ where: { userId } });
      let daysToAdd = 30;
      if (sub.plan === 'diario') daysToAdd = 1;
      if (sub.plan === 'trimestral') daysToAdd = 90;

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + daysToAdd);

      await prisma.subscription.update({
        where: { userId },
        data: {
          status: 'active',
          expiresAt: expiresAt
        }
      });

      return res.json({ status: 'approved', expiresAt });
    }

    res.json({ status: data.status }); // 'pending', 'rejected', etc
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao consultar pagamento.' });
  }
});


// Inicialização
app.listen(PORT, () => {
  console.log(`Backend RotaZAP rodando na porta ${PORT}`);
});
