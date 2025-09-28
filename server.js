//==API TOMORA - Pedro Staiger==\\
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import path from 'path';
import { fileURLToPath } from 'url';  // ✅ JÁ PRESENTE
import { dirname } from 'path';       // ✅ JÁ PRESENTE

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

// ✅ JÁ PRESENTE:
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

//Busca informações de um usuário específico
app.post('/usersSearch', async (req, res) => {
  try {
    const user = await prisma.user.findFirst({
      where: {
        id: req.body.id
      }
    });

    if (!user) {
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
    console.error("Erro ao consultar usuário: " + error);
    res.status(500).json({ error: 'Failed to search' });
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

//Deslinka usuários
app.post('/usersDeslink', async (req, res) => {
  try {
    const { userId } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { linkedId: null },
    });

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Erro ao deslinkar conta: " + error);
    res.status(500).json({ error: 'Falha ao deslinkar contas'});
  }
});

//Deleta usuários
app.post('usersDelete', async (req, res) => {
  try {
    await prisma.user.delete({
      where: {
        id: req.body.id
      }
    });

    res.status(200).json({ message: "Usuário excluído com sucesso." });
  } catch (error) {
    res.status(500).json({ error: "Erro ao excluir usuário." });
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
        userId: req.body.searchId
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

// Simula armazenamento temporário de códigos de autorização
const authCodes = new Map();

// ✅ ADICIONAR ESTE ENDPOINT ANTES DO /auth:
app.get('/login', (req, res) => {
  // Retorna a página HTML
  res.sendFile(path.join(__dirname, 'login.html'));
});

// ✅ ENDPOINT /auth COM LOGS:
app.get('/auth', async (req, res) => {
  console.log('=== DEBUG AUTH ===');
  console.log('Query recebida:', JSON.stringify(req.query, null, 2));
  
  const { response_type, client_id, state, redirect_uri, email, password } = req.query;

  // Valida parâmetros OAuth
  if (response_type !== 'code' || client_id !== CLIENT_ID) {
    console.log('❌ Parametros OAuth inválidos:', { response_type, client_id });
    return res.status(400).json({ error: 'Parâmetros OAuth inválidos' });
  }

  // ✅ Se não tem email/senha, redireciona para página de login
  if (!email || !password) {
    console.log('📝 Sem credenciais - redirecionando para login');
    const loginUrl = `/login?${new URLSearchParams({
      response_type,
      client_id,
      state,
      redirect_uri
    })}`;
    console.log('Login URL:', loginUrl);
    return res.redirect(loginUrl);
  }

  console.log('🔍 Validando credenciais para email:', email);

  // Valida credenciais no banco
  try {
    const user = await prisma.user.findFirst({
      where: { email }
    });

    console.log('🔍 Resultado da busca do usuário:', user ? 'ENCONTRADO' : 'NÃO_ENCONTRADO');
    if (user) {
      console.log('👤 Usuário:', { id: user.id, name: user.name, email: user.email });
    }

    if (!user || user.password !== password) {
      console.log('❌ Credenciais inválidas');
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gera código de autorização
    const code = `code_${Date.now()}_${Math.random().toString(36).substring(2)}`;
    authCodes.set(code, {
      userId: user.id,
      expires: Date.now() + 30 * 60 * 1000 // 30 minutos para debug
    });

    console.log('🎫 Código de autorização gerado:', code);
    console.log('📊 Total de códigos em storage:', authCodes.size);

    // Redireciona de volta para Alexa
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append('code', code);
    redirectUrl.searchParams.append('state', state);
    
    console.log('🔄 Redirecionando para:', redirectUrl.toString());
    res.redirect(redirectUrl.toString());
    
  } catch (error) {
    console.error('💥 Erro no /auth:', error);
    res.status(500).json({ error: 'Falha ao autenticar' });
  }
});

// Endpoint para trocar code por access_token
app.post('/token', async (req, res) => {
  console.log('=== DEBUG TOKEN ===');
  console.log('Body recebido:', JSON.stringify(req.body, null, 2));
  console.log('📊 Códigos em storage:', authCodes.size);
  
  const { grant_type, code, client_id } = req.body; // ✅ REMOVIDO client_secret

  // ✅ Valida parâmetros (SEM exigir client_secret)
  if (
    grant_type !== 'authorization_code' ||
    client_id !== CLIENT_ID
  ) {
    console.log('❌ Credenciais inválidas:', { grant_type, client_id });
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  console.log('🔍 Procurando código:', code);

  // Verifica o código de autorização
  const authData = authCodes.get(code);
  if (!authData) {
    console.log('❌ Código não encontrado no storage');
    console.log('📋 Códigos disponíveis:', Array.from(authCodes.keys()));
    return res.status(400).json({ error: 'Código inválido ou expirado' });
  }

  if (authData.expires < Date.now()) {
    console.log('❌ Código expirado');
    authCodes.delete(code);
    return res.status(400).json({ error: 'Código inválido ou expirado' });
  }

  console.log('✅ Código válido encontrado para userId:', authData.userId);

  // Gera um access_token
  const accessToken = Buffer.from(JSON.stringify({ userId: authData.userId })).toString('base64');

  // Remove o código após uso
  authCodes.delete(code);

  console.log('🎫 Access token gerado:', accessToken.substring(0, 20) + '...');
  console.log('🗑️ Código removido do storage');

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
  console.log("🔍 Token recebido:", token ? token.substring(0, 50) + "..." : "NULL");

  try {
    // Verifica se é um JWT da Alexa (começa com 'eyJ')
    if (token && token.startsWith('eyJ')) {
      console.log("🔍 Token JWT da Alexa detectado");
      
      // Para desenvolvimento, mapeia para um usuário padrão
      // Você pode alterar este ID para qualquer usuário que existe no seu banco
      const defaultUserId = "68d5251ffe2b086b370cd59e"; // <<<< ALTERE ESTE NÚMERO
      
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
    console.log("🔍 Tentando decodificar como base64 simples");
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

//==ENDPOINTS DE SINCRONIZAÇÃO PARA ALEXA==\\
// Sincroniza lembretes da Alexa com o banco de dados
app.post('/sync-alexa-reminders', async (req, res) => {
  try {
    console.log("🔄 === INICIANDO SINCRONIZAÇÃO DE LEMBRETES DA ALEXA ===");
    
    const { userId, lembretes } = req.body;
    
    // Validação de entrada
    if (!userId) {
      console.log("❌ UserId não fornecido");
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    
    if (!Array.isArray(lembretes)) {
      console.log("❌ Lembretes deve ser um array");
      return res.status(400).json({ error: 'lembretes deve ser um array' });
    }
    
    console.log(`📋 Sincronizando ${lembretes.length} lembretes para userId: ${userId}`);
    
    // Verifica se o usuário existe
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });
    
    if (!user) {
      console.log("❌ Usuário não encontrado:", userId);
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    console.log(`✅ Usuário encontrado: ${user.name}`);
    
    let sincronizados = 0;
    let erros = 0;
    
    // Processa cada lembrete da Alexa
    for (const lembrete of lembretes) {
      try {
        console.log(`🔄 Processando lembrete:`, {
          id: lembrete.id,
          status: lembrete.status,
          mensagem: lembrete.mensagem?.substring(0, 50) + "..."
        });
        
        // Extrai informações do lembrete
        const mensagem = lembrete.mensagem || '';
        const scheduledTime = lembrete.hora || '';
        
        // Tenta extrair nome do remédio da mensagem
        // Ex: "Você precisa tomar Dipirona, 500mg."
        const medicineMatch = mensagem.match(/tomar\s+([^,\.]+)/i);
        const nomeRemedio = medicineMatch ? medicineMatch[1].trim() : 'Remédio não identificado';
        
        // Tenta extrair dosagem
        const dosageMatch = mensagem.match(/,\s*([^\.]+)/);
        const dosagem = dosageMatch ? dosageMatch[1].trim() : null;
        
        // Extrai hora do scheduledTime (formato: "2024-12-25T14:30:00")
        let hora = null;
        if (scheduledTime) {
          const timeFromSchedule = scheduledTime.split('T')[1]?.substring(0, 5); // "14:30"
          hora = timeFromSchedule;
        }
        
        console.log(`🔍 Dados extraídos:`, {
          remedio: nomeRemedio,
          dosagem: dosagem,
          hora: hora
        });
        
        // Verifica se já existe um lembrete similar no banco
        const existingReminder = await prisma.reminder.findFirst({
          where: {
            userId: userId,
            name: nomeRemedio,
            hour: hora
          }
        });
        
        if (existingReminder) {
          console.log(`⭐️ Lembrete já existe no banco - pulando:`, nomeRemedio);
          continue;
        }
        
        // Cria novo lembrete no banco apenas se não existir
        if (nomeRemedio !== 'Remédio não identificado' && hora) {
          const novoLembrete = await prisma.reminder.create({
            data: {
              userId: userId,
              name: nomeRemedio,
              dosage: dosagem,
              desc: `Sincronizado da Alexa - ID: ${lembrete.id}`,
              hour: hora
            }
          });
          
          console.log(`✅ Lembrete criado no banco:`, {
            id: novoLembrete.id,
            name: novoLembrete.name,
            hour: novoLembrete.hour
          });
          
          sincronizados++;
        } else {
          console.log(`⚠️ Dados insuficientes para criar lembrete:`, {
            remedio: nomeRemedio,
            hora: hora
          });
        }
        
      } catch (lembreteError) {
        console.log(`❌ Erro ao processar lembrete individual:`, lembreteError.message);
        erros++;
      }
    }
    
    const resultado = {
      message: 'Sincronização concluída',
      processados: lembretes.length,
      sincronizados: sincronizados,
      erros: erros,
      userId: userId
    };
    
    console.log(`📊 Resultado da sincronização:`, resultado);
    console.log("🔄 === FIM SINCRONIZAÇÃO DE LEMBRETES DA ALEXA ===");
    
    res.status(200).json(resultado);
    
  } catch (error) {
    console.error('❌ ERRO na sincronização de lembretes da Alexa:', error);
    res.status(500).json({ 
      error: 'Falha na sincronização de lembretes',
      details: error.message 
    });
  }
});

// Endpoint para sincronização de histórico (criar registros baseados em atividade)
app.post('/sync-history', async (req, res) => {
  try {
    console.log("📚 === INICIANDO SINCRONIZAÇÃO DE HISTÓRICO ===");
    
    const { userId, atividades } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    
    // Verifica se o usuário existe
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });
    
    if (!user) {
      console.log("❌ Usuário não encontrado:", userId);
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    console.log(`✅ Sincronizando histórico para: ${user.name}`);
    
    // Se não há atividades específicas, pode criar um registro de sincronização
    if (!atividades || atividades.length === 0) {
      console.log("📝 Criando registro de sincronização automática");
      
      await prisma.history.create({
        data: {
          userId: userId,
          reminderId: null,
          name: "Sincronização Alexa",
          hour: new Date().toTimeString().substring(0, 5), // HH:MM atual
          taken: false
        }
      });
      
      console.log("✅ Registro de sincronização criado");
    } else {
      // Processa atividades específicas se fornecidas
      for (const atividade of atividades) {
        await prisma.history.create({
          data: {
            userId: userId,
            reminderId: atividade.reminderId || null,
            name: atividade.name || "Atividade não identificada",
            hour: atividade.hour || new Date().toTimeString().substring(0, 5),
            taken: atividade.taken || false
          }
        });
      }
      
      console.log(`✅ ${atividades.length} atividades registradas no histórico`);
    }
    
    console.log("📚 === FIM SINCRONIZAÇÃO DE HISTÓRICO ===");
    
    res.status(200).json({ 
      message: 'Histórico sincronizado com sucesso',
      userId: userId 
    });
    
  } catch (error) {
    console.error('❌ ERRO na sincronização de histórico:', error);
    res.status(500).json({ 
      error: 'Falha na sincronização de histórico',
      details: error.message 
    });
  }
});

// Endpoint para sincronização completa (lembretes + histórico + verificações)
app.post('/sync-complete', async (req, res) => {
  try {
    console.log("🔄 === INICIANDO SINCRONIZAÇÃO COMPLETA ===");
    
    const { userId, lembretes, atividades } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    
    // Verifica se o usuário existe
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    console.log(`🔄 Sincronização completa para: ${user.name}`);
    
    const resultado = {
      userId: userId,
      userName: user.name,
      lembretesSincronizados: 0,
      atividadesRegistradas: 0,
      erros: [],
      timestamp: new Date().toISOString()
    };
    
    // Sincroniza lembretes se fornecidos
    if (lembretes && Array.isArray(lembretes) && lembretes.length > 0) {
      try {
        // Reutiliza a lógica do endpoint de lembretes
        for (const lembrete of lembretes) {
          // Processa cada lembrete (lógica similar ao endpoint anterior)
          const mensagem = lembrete.mensagem || '';
          const medicineMatch = mensagem.match(/tomar\s+([^,\.]+)/i);
          const nomeRemedio = medicineMatch ? medicineMatch[1].trim() : null;
          
          if (nomeRemedio) {
            const scheduledTime = lembrete.hora || '';
            const hora = scheduledTime.split('T')[1]?.substring(0, 5);
            
            if (hora) {
              // Verifica se já existe
              const existing = await prisma.reminder.findFirst({
                where: { userId, name: nomeRemedio, hour: hora }
              });
              
              if (!existing) {
                await prisma.reminder.create({
                  data: {
                    userId,
                    name: nomeRemedio,
                    dosage: null,
                    desc: `Sync completa - ${new Date().toLocaleDateString()}`,
                    hour: hora
                  }
                });
                resultado.lembretesSincronizados++;
              }
            }
          }
        }
      } catch (lembretesError) {
        resultado.erros.push(`Erro nos lembretes: ${lembretesError.message}`);
      }
    }
    
    // Registra atividades se fornecidas
    if (atividades && Array.isArray(atividades) && atividades.length > 0) {
      try {
        for (const atividade of atividades) {
          await prisma.history.create({
            data: {
              userId,
              reminderId: atividade.reminderId || null,
              name: atividade.name || "Atividade sincronizada",
              hour: atividade.hour || new Date().toTimeString().substring(0, 5),
              taken: atividade.taken || false
            }
          });
          resultado.atividadesRegistradas++;
        }
      } catch (atividadesError) {
        resultado.erros.push(`Erro nas atividades: ${atividadesError.message}`);
      }
    }
    
    // Cria um registro de sincronização no histórico
    await prisma.history.create({
      data: {
        userId,
        reminderId: null,
        name: "Sincronização Completa Alexa",
        hour: new Date().toTimeString().substring(0, 5),
        taken: false
      }
    });
    
    console.log("📊 Resultado da sincronização completa:", resultado);
    console.log("🔄 === FIM SINCRONIZAÇÃO COMPLETA ===");
    
    res.status(200).json(resultado);
    
  } catch (error) {
    console.error('❌ ERRO na sincronização completa:', error);
    res.status(500).json({ 
      error: 'Falha na sincronização completa',
      details: error.message 
    });
  }
});

// Endpoint para verificar status de sincronização
app.post('/sync-status', async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'userId é obrigatório' });
    }
    
    // Busca estatísticas do usuário
    const [user, reminders, history] = await Promise.all([
      prisma.user.findUnique({ where: { id: userId } }),
      prisma.reminder.findMany({ 
        where: { userId },
        orderBy: { id: 'desc' }
      }),
      prisma.history.findMany({ 
        where: { userId },
        orderBy: { id: 'desc' },
        take: 10 // Últimos 10 registros
      })
    ]);
    
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    const ultimaSincronizacao = history.find(h => 
      h.name.includes('Sincronização') || h.name.includes('Alexa')
    );
    
    res.status(200).json({
      userId: userId,
      userName: user.name,
      totalReminders: reminders.length,
      totalHistoryEntries: history.length,
      ultimaSincronizacao: ultimaSincronizacao?.createdAt || null,
      remindersRecentes: reminders.slice(0, 5).map(r => ({
        name: r.name,
        hour: r.hour,
        dosage: r.dosage
      })),
      atividadesRecentes: history.slice(0, 5).map(h => ({
        name: h.name,
        hour: h.hour,
        taken: h.taken
      }))
    });
    
  } catch (error) {
    console.error('❌ Erro ao verificar status:', error);
    res.status(500).json({ 
      error: 'Falha ao verificar status',
      details: error.message 
    });
  }
});

// Inicialização
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
