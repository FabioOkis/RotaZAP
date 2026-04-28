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
const APP_URL = process.env.APP_URL || 'http://72.60.250.170';

// Configurações Globais
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- MIDDLEWARES ---

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

const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
  }
};

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'E-mail já está em uso.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await prisma.user.create({
      data: { name, email, password: hashedPassword, role: 'user' }
    });
    res.status(201).json({ message: 'Usuário criado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = req.body.email || req.body.username;
    const password = req.body.password;

    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Credenciais inválidas.' });

    if (!user.isActive) return res.status(403).json({ error: 'Sua conta está desativada. Entre em contato com o suporte.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Credenciais inválidas.' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, name: true, email: true, role: true, isActive: true }
    });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar perfil' });
  }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { name: true, email: true, role: true, createdAt: true, subscription: true }
    });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar dados do usuário.' });
  }
});

app.get('/api/payments/history', authenticateToken, async (req, res) => {
  try {
    const payments = await prisma.payment.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' }
    });
    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar histórico.' });
  }
});

// --- ROTAS ADMINISTRATIVAS ---

app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const totalUsers = await prisma.user.count({ where: { role: 'user' } });
    const activeSubs = await prisma.subscription.count({ where: { status: 'active' } });
    const routesToday = await prisma.routeDailyUsage.aggregate({
      where: { date: new Date().toISOString().split('T')[0] },
      _sum: { count: true }
    });
    res.json({
      total_users: totalUsers,
      active_users: activeSubs,
      routes_today: routesToday._sum.count || 0,
      total_deliveries: 0,
      completion_rate: 0,
      total_revenue: 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas.' });
  }
});

app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: { role: 'user' },
      include: { subscription: true, _count: { select: { dailyUsages: true } } },
      orderBy: { createdAt: 'desc' }
    });
    const formattedUsers = users.map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      is_active: u.isActive,
      total_routes: 0,
      total_deliveries: 0,
      plan: u.subscription?.plan || 'free'
    }));
    res.json(formattedUsers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao buscar usuários.' });
  }
});

app.post('/api/admin/users/:id/reset-password', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await prisma.user.update({ where: { id: parseInt(id) }, data: { password: hashedPassword } });
    res.json({ message: 'Senha redefinida com sucesso!' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao redefinir senha.' });
  }
});

app.put('/api/admin/users/:id/toggle-active', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    await prisma.user.update({ where: { id: parseInt(id) }, data: { isActive: !user.isActive } });
    res.json({ message: `Usuário ${user.isActive ? 'desativado' : 'ativado'} com sucesso!` });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao alterar status do usuário.' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.user.delete({ where: { id: parseInt(id) } });
    res.json({ message: 'Usuário excluído com sucesso!' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir usuário.' });
  }
});

// --- ROTAS DE LIMITES E ROTAS ---

app.post('/api/routes/add', authenticateToken, async (req, res) => {
  try {
    const { numberOfRoutesToAdd } = req.body;
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];

    const subscription = await prisma.subscription.findUnique({ where: { userId } });
    const isActive = subscription && subscription.status === 'active' && subscription.expiresAt > new Date();

    if (isActive) return res.json({ allowed: true, message: 'Rotas adicionadas (plano premium)' });

    let usage = await prisma.routeDailyUsage.findUnique({
      where: { userId_date: { userId, date: today } }
    });

    if (!usage) {
      usage = await prisma.routeDailyUsage.create({ data: { userId, date: today, count: 0 } });
    }

    if (usage.count + numberOfRoutesToAdd > 10) {
      return res.status(403).json({
        allowed: false,
        error: 'Limite diário de 10 rotas excedido.',
        currentUsage: usage.count,
        limit: 10
      });
    }

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
    const { plan } = req.body;
    const userId = req.user.id;

    let amount = 0;
    let days = 0;

    if (plan === 'diario')       { amount = 1.00;  days = 1;  }
    else if (plan === 'mensal')  { amount = 20.00; days = 30; }
    else if (plan === 'trimestral') { amount = 50.00; days = 90; }
    else return res.status(400).json({ error: 'Plano inválido' });

    const response = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Idempotency-Key': `${userId}-${Date.now()}`
      },
      body: JSON.stringify({
        transaction_amount: amount,
        description: `RotaZAP - Plano ${plan}`,
        payment_method_id: 'pix',
        payer: { email: req.user.email }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Erro Mercado Pago:', data);
      return res.status(500).json({ error: 'Falha ao comunicar com o Mercado Pago.' });
    }

    // Salvar assinatura como pendente
    await prisma.subscription.upsert({
      where: { userId: req.user.id },
      update: { mpPreferenceId: data.id.toString(), status: 'pending', plan },
      create: { userId: req.user.id, mpPreferenceId: data.id.toString(), status: 'pending', plan }
    });

    // ✅ CORREÇÃO: usar variável 'amount' no lugar de 'transaction_amount' (que não existia)
    await prisma.payment.upsert({
      where: { mpId: data.id.toString() },
      update: { status: 'pending' },
      create: {
        userId: req.user.id,
        mpId: data.id.toString(),
        status: 'pending',
        amount: amount,   // <-- corrigido
        plan: plan
      }
    });

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

app.get('/api/payments/status/:paymentId', authenticateToken, async (req, res) => {
  try {
    const { paymentId } = req.params;
    const userId = req.user.id;

    const response = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
      headers: { 'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}` }
    });

    const data = await response.json();

    if (data.status === 'approved') {
      const sub = await prisma.subscription.findUnique({ where: { userId } });
      let daysToAdd = 30;
      if (sub?.plan === 'diario')      daysToAdd = 1;
      if (sub?.plan === 'trimestral')  daysToAdd = 90;

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + daysToAdd);

      await prisma.subscription.update({
        where: { userId },
        data: { status: 'active', expiresAt }
      });

      // Atualizar histórico de pagamento como aprovado
      await prisma.payment.update({
        where: { mpId: paymentId.toString() },
        data: { status: 'approved' }
      }).catch(() => {}); // silencia se não encontrar

      return res.json({ status: 'approved', expiresAt });
    }

    res.json({ status: data.status });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao consultar pagamento.' });
  }
});

app.post('/api/payments/checkout', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;

    let amount = 0;
    if (plan === 'diario')          amount = 1.00;
    else if (plan === 'mensal')     amount = 20.00;
    else if (plan === 'trimestral') amount = 50.00;
    else return res.status(400).json({ error: 'Plano inválido' });

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items: [{
          title: `RotaZAP - Plano ${plan}`,
          unit_price: amount,
          quantity: 1,
          currency_id: 'BRL'
        }],
        back_urls: {
          // ✅ CORREÇÃO: usando APP_URL do .env em vez de IP hardcoded
          success: `${APP_URL}/dashboard.html?status=success`,
          failure: `${APP_URL}/payment.html?status=failure`,
          pending: `${APP_URL}/payment.html?status=pending`
        },
        auto_return: 'approved',
        // ✅ CORREÇÃO: usando WEBHOOK_URL do .env
        notification_url: process.env.WEBHOOK_URL || `${APP_URL}/api/webhook`,
        external_reference: req.user.id.toString()
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Erro Checkout Pro:', data);
      return res.status(500).json({ error: 'Erro ao gerar link de pagamento.' });
    }

    res.json({ init_point: data.init_point });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao gerar link de pagamento.' });
  }
});

// --- WEBHOOK MERCADO PAGO ---

app.post('/api/webhook', async (req, res) => {
  try {
    const { type, data } = req.body;

    if (type === 'payment') {
      const paymentId = data.id;

      const response = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { 'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}` }
      });
      const payment = await response.json();

      if (payment.status === 'approved') {
        const userId = parseInt(payment.external_reference);
        if (!userId) return res.sendStatus(200);

        let plan = 'mensal';
        if (payment.transaction_amount <= 1.5) plan = 'diario';
        else if (payment.transaction_amount >= 45) plan = 'trimestral';

        let days = 30;
        if (plan === 'diario')      days = 1;
        if (plan === 'trimestral')  days = 90;

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);

        await prisma.subscription.upsert({
          where: { userId },
          update: { status: 'active', plan, expiresAt },
          create: { userId, status: 'active', plan, expiresAt }
        });

        await prisma.payment.upsert({
          where: { mpId: paymentId.toString() },
          update: { status: 'approved' },
          create: {
            userId,
            mpId: paymentId.toString(),
            status: 'approved',
            amount: payment.transaction_amount,
            plan
          }
        });
      }
    }

    res.sendStatus(200); // MP exige sempre 200
  } catch (error) {
    console.error('Webhook Error:', error);
    res.sendStatus(200);
  }
});

// --- INICIALIZAÇÃO ---

app.listen(PORT, () => {
  console.log(`✅ Backend RotaZAP rodando na porta ${PORT}`);
  console.log(`📦 Mercado Pago configurado: ${process.env.MP_ACCESS_TOKEN ? 'SIM' : 'NÃO - verifique o .env'}`);
});
