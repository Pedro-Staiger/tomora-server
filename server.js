//==API TOMORA - Pedro Staiger==\\
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';

const app = express();
app.use(express.json());
app.use(cors());

const prisma = new PrismaClient();

//==USUÁRIOS==\\
//Cria usuário
app.post('/usersCreate', async (req, res) => {
  try {
    const user = await prisma.user.create({
      data: {
        email: req.body.email,
        name: req.body.name,
        password: req.body.password,
        isMedicado: req.body.isMedicado,
        isAuxiliar: req.body.isAuxiliar,      
      }
    });
    res.status(201).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Falha ao criar usuário' });
  }
});

//Efetua o login
app.post('/usersLogin', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findFirst({
      where: {
        email: email
      }
    });

    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const passwordMatch = password === user.password;
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    res.status(200).json({
      id: user.id,
      email: user.email,
      name: user.name,
      isMedicado: user.isMedicado,
      isAuxiliar: user.isAuxiliar,
      linkedId: user.linkedId
    });
  } catch (error) {
    console.error("Erro ao fazer login: " + error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

//Linka usuários
app.post('/usersLink', async (req, res) => {
  try {
    const { userId, linkedId } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { linkedId },
    });

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Erro ao linkar conta: " + error);
    res.status(500).json({ error: 'Falha ao linkar contas'});
  }
});

//==LEMBRETES==\\
//Cria lembrete
app.post('/remindersCreate', async (req, res) => {
  try {
    const reminder = await prisma.reminder.create({
      data: {
        userId: req.body.userId,
        name: req.body.name,
        dosage: req.body.dosage,
        desc: req.body.desc,
        hour: req.body.hour,
      }
    });
    res.status(201).json(reminder);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create reminder' });
  }
});

//Consulta lembretes de um usuário específico
app.post('/remindersSearch', async (req, res) => {
  try {
    const reminders = await prisma.reminder.findMany({
      where: {
        userId: req.body.searchId
      },
      orderBy: {
        id: 'desc'
      }
    });
    res.status(200).json(reminders);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Falha ao consultar lembretes' });
  }
});

//Retorna o lembrete mais próximo ao horário atual
app.post('/reminderNearest', async (req, res) => {
  try {
    //Extração e validação dos dados de entrada
    const userId = req.body.userId;
    const hour = req.body.hour;
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    if (!hour || !/^\d{2}:\d{2}$/.test(hour)) {
      return res.status(400).json({ error: 'hour deve estar no formato HH:mm' });
    }

    //Busca todos os lembretes do usuário
    const reminders = await prisma.reminder.findMany({
      where: {
        userId: userId,
      },
      orderBy: {
        hour: 'asc',
      },
    });

    //Verifica se há lembretes
    if (!reminders || reminders.length === 0) {
      return res.status(404).json({ error: 'Nenhum lembrete cadastrado' });
    }

    //Encontra o primeiro lembrete futuro (hour >= req.body.hour)
    const futureReminder = reminders.find(reminder => reminder.hour >= hour);

    //Se houver lembrete futuro, retorna o primeiro; caso contrário, retorna o primeiro disponível
    const nearestReminder = futureReminder || reminders[0];

    res.status(200).json(nearestReminder);
  } catch (error) {
    console.error('Erro ao consultar lembrete mais próximo:', error);
    res.status(500).json({ error: 'Falha ao consultar próximo lembrete!' });
  }
});

// Atualiza os lembretes (permite atualização parcial)
app.post('/remindersUpdate', async (req, res) => {
  try {
    const data = {};
    if (req.body.name) data.name = req.body.name;
    if (req.body.dosage) data.dosage = req.body.dosage;
    if (req.body.desc) data.desc = req.body.desc;
    if (req.body.hour) data.hour = req.body.hour;

    if (Object.keys(data).length === 0) {
      return res.status(400).json({ error: 'Pelo menos um campo deve ser fornecido' });
    }

    const updatedReminder = await prisma.reminder.update({
      where: { id: req.body.id },
      data
    });

    res.status(200).json(updatedReminder);
  } catch (error) {
    console.error("Erro ao atualizar lembrete:", error);
    res.status(500).json({ error: "Falha ao atualizar lembrete" });
  }
});

//Deletar lembretes
app.post('/remindersDelete', async (req, res) => {
  try {
    await prisma.reminder.delete({
      where: {
        id: req.body.id
      }
    });

    res.status(200).json({ message: "Lembrete excluído com sucesso." });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir lembrete." });
  }
});

//Deleta o lembrete mais próximo ao horário atual
app.post('/reminderNearestDelete', async (req, res) => {
  try {
    //Extração e validação dos dados de entrada
    const userId = req.body.userId;
    const hour = req.body.hour;
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    if (!hour || !/^\d{2}:\d{2}$/.test(hour)) {
      return res.status(400).json({ error: 'hour deve estar no formato HH:mm' });
    }

    //Busca todos os lembretes do usuário
    const reminders = await prisma.reminder.findMany({
      where: {
        userId: userId,
      },
      orderBy: {
        hour: 'asc',
      },
    });

    //Verifica se há lembretes
    if (!reminders || reminders.length === 0) {
      return res.status(404).json({ error: 'Nenhum lembrete cadastrado' });
    }

    //Encontra o primeiro lembrete futuro (hour >= req.body.hour)
    const futureReminder = reminders.find(reminder => reminder.hour >= hour);

    //Se houver lembrete futuro, retorna o primeiro; caso contrário, retorna o primeiro disponível
    const nearestReminder = futureReminder || reminders[0];

    await prisma.reminder.delete({
      where: {
        id: nearestReminder.id
      }
    });
    
    res.status(200).json(nearestReminder);
  } catch (error) {
    console.error('Erro ao consultar lembrete mais próximo:', error);
    res.status(500).json({ error: 'Falha ao consultar próximo lembrete!' });
  }
});

//==HISTÓRICO==\\
//Cria histórico
app.post('/historyCreate', async (req, res) => {
  try {
    const history = await prisma.history.create({
      data: {
        userId: req.body.userId,
        reminderId: req.body.reminderId,
        name: req.body.name,
        hour: req.body.hour,
        taken: req.body.taken
      }
    });
    res.status(201).json(history);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Falha ao criar histórico' });
  }
});

//Consulta histórico de um usuário específico
app.post('/historySearch', async (req, res) => {
  try {
    const histories = await prisma.history.findMany({
      where: {
        userId: req.body.userId
      },
      orderBy: {
        id: 'desc'
      }
    });
    res.status(200).json(histories);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Falha ao consultar histórico' });
  }
});

//==ACCOUNT LINKING PARA ALEXA==\\
// Configurações para testes
const CLIENT_ID = 'tomora-skill-test-1234567890';
const CLIENT_SECRET = 'x9kPqW7mZ3tR8vY2nJ5bL6cF4hT1rQ8w';

// Simula armazenamento temporário de códigos de autorização (em produção, use Redis ou DB com expiração)
const authCodes = new Map(); // Map para armazenar { code: { userId, expires } }

// Endpoint de autorização (OAuth 2.0)
app.get('/auth', async (req, res) => {
  const { response_type, client_id, state, redirect_uri } = req.query;

  // Valida parâmetros
  if (response_type !== 'code' || client_id !== CLIENT_ID) {
    return res.status(400).json({ error: 'Parâmetros inválidos' });
  }

  // Para testes, simulamos um login com email/senha fixos
  // Substitua por uma página de login real ou integração com o app
  const email = req.query.email || 'test@example.com'; // Para testes, hardcoded
  const password = req.query.password || 'teste123'; // Para testes, hardcoded

  try {
    const user = await prisma.user.findFirst({
      where: { email }
    });

    if (!user || user.password !== password) { // Ajuste para bcrypt.compare se usar hash
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gera um código de autorização único
    const code = `code_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    authCodes.set(code, {
      userId: user.id,
      expires: Date.now() + 5 * 60 * 1000 // Expira em 5 minutos
    });

    // Redireciona para o redirect_uri com o code e state
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append('code', code);
    redirectUrl.searchParams.append('state', state);
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('Erro no /auth:', error);
    res.status(500).json({ error: 'Falha ao autenticar' });
  }
});

// Endpoint para trocar code por access_token
app.post('/token', async (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;

  // Valida parâmetros
  if (
    grant_type !== 'authorization_code' ||
    client_id !== CLIENT_ID ||
    client_secret !== CLIENT_SECRET
  ) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // Verifica o código de autorização
  const authData = authCodes.get(code);
  if (!authData || authData.expires < Date.now()) {
    return res.status(400).json({ error: 'Código inválido ou expirado' });
  }

  // Gera um access_token (para testes, codificamos o userId em base64)
  const accessToken = Buffer.from(JSON.stringify({ userId: authData.userId })).toString('base64');

  // Remove o código após uso
  authCodes.delete(code);

  res.status(200).json({
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: 3600 // 1 hora
  });
});

// Endpoint para validar access_token (usado pela skill)
app.post('/validate-token', async (req, res) => {
  const { token } = req.body;
  
  console.log("🔍 === INICIANDO /validate-token ===");
  console.log("📝 Token recebido:", token ? token.substring(0, 50) + "..." : "NULL");

  try {
    // Verifica se é um JWT da Alexa (começa com 'eyJ')
    if (token && token.startsWith('eyJ')) {
      console.log("🔐 Token JWT da Alexa detectado");
      
      // Para desenvolvimento, mapeia para um usuário padrão
      // Você pode alterar este ID para qualquer usuário que existe no seu banco
      const defaultUserId = "68d45095e7797492cd2c8b75"; // <<<< ALTERE ESTE NÚMERO
      
      console.log("👤 Tentando usar userId padrão:", defaultUserId);
      
      // Verifica se o usuário padrão existe
      const user = await prisma.user.findUnique({
        where: { id: defaultUserId }
      });

      if (user) {
        console.log("✅ Usuário padrão encontrado:", user.name);
        return res.status(200).json({ userId: defaultUserId });
      }
      
      // Se não existe o userId padrão, pega o primeiro usuário disponível
      console.log("⚠️ Usuário padrão não encontrado, buscando primeiro disponível...");
      const firstUser = await prisma.user.findFirst();
      
      if (!firstUser) {
        console.log("❌ Nenhum usuário encontrado no sistema");
        return res.status(401).json({ error: 'Nenhum usuário encontrado no sistema' });
      }
      
      console.log("✅ Usando primeiro usuário disponível:", firstUser.name, "ID:", firstUser.id);
      return res.status(200).json({ userId: firstUser.id });
    }
    
    // Se não é JWT, tenta decodificar como base64 simples (seu formato original)
    console.log("📝 Tentando decodificar como base64 simples");
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
    const userId = decoded.userId;

    console.log("🆔 UserId extraído do token base64:", userId);

    // Verifica se o usuário existe
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      console.log("❌ Usuário não encontrado para ID:", userId);
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    console.log("✅ Usuário encontrado:", user.name);
    return res.status(200).json({ userId });

  } catch (error) {
    console.log("🚫 ERRO no /validate-token:");
    console.log("🚫 Erro message:", error.message);
    console.log("🚫 Erro stack:", error.stack);
    res.status(400).json({ error: 'Token inválido', details: error.message });
  } finally {
    console.log("🔍 === FIM /validate-token ===");
  }
});

// Inicialização
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
