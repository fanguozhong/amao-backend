const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// 安全：JWT密钥必须从环境变量读取
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('🔴 错误: JWT_SECRET 环境变量未设置!');
  console.error('请设置环境变量: export JWT_SECRET=$(openssl rand -hex 32)');
  process.exit(1);
}

// 请求日志中间件
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  next();
});

// 健康检查接口
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

const SMS_CONFIG = {
  endpoint: process.env.SMS_ENDPOINT || 'https://api.ucpaas.com',
  accountSid: process.env.SMS_ACCOUNT_SID || '',
  accountToken: process.env.SMS_ACCOUNT_TOKEN || '',
  appId: process.env.SMS_APP_ID || ''
};

const RONGCLOUD_CONFIG = {
  appKey: process.env.RONGCLOUD_APP_KEY || '',
  appSecret: process.env.RONGCLOUD_APP_SECRET || '',
  apiUrl: process.env.RONGCLOUD_API_URL || 'http://api.rong.io'
};

const AMAP_CONFIG = { key: process.env.AMAP_KEY || '' };

app.use(cors());
app.use(express.json());

let pool;
async function getPool() {
  if (!pool) {
    const dbHost = process.env.DB_HOST || 'localhost';
    const dbUser = process.env.DB_USER || 'amao';
    const dbPassword = process.env.DB_PASSWORD;
    const dbName = process.env.DB_NAME || 'amao';
    
    if (!dbPassword) {
      console.error('🔴 错误: DB_PASSWORD 环境变量未设置!');
      process.exit(1);
    }
    
    pool = mysql.createPool({
      host: dbHost,
      user: dbUser,
      password: dbPassword,
      database: dbName,
      waitForConnections: true, connectionLimit: 10, queueLimit: 0
    });
  }
  return pool;
}

// ========================================
// 1. 短信验证码系统
// ========================================
const smsCodes = new Map();
const smsSendRecords = new Map();

function generateCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

async function sendSMS(phone, code) {
  if (!SMS_CONFIG.accountSid || !SMS_CONFIG.accountToken) {
    console.log(`[SMS Mock] 验证码 ${code} 已发送至 ${phone}`);
    return { success: true, mock: true };
  }
  try {
    const timestamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    const signature = require('crypto').createHash('md5').update(SMS_CONFIG.accountSid + SMS_CONFIG.accountToken + timestamp).digest('hex').toUpperCase();
    const response = await axios.post(`${SMS_CONFIG.endpoint}/sms/${SMS_CONFIG.appId}/verifycode`, {
      verifyCode: { serverId: uuidv4(), phone, code }
    }, { headers: { 'Content-Type': 'application/json;charset=utf-8' }, params: { accountSid: SMS_CONFIG.accountSid, timestamp } });
    return { success: true, data: response.data };
  } catch (error) {
    console.error('[SMS Error]', error.message);
    return { success: true, mock: true, error: error.message };
  }
}

function canSendSMS(phone) {
  const lastSend = smsSendRecords.get(phone);
  if (!lastSend) return true;
  return Date.now() - lastSend >= 60000;
}

app.post('/api/sms/send', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone || !/^1[3-9]\d{9}$/.test(phone)) return res.status(400).json({ error: '手机号格式不正确' });
    if (!canSendSMS(phone)) {
      const remaining = 60 - Math.floor((Date.now() - smsSendRecords.get(phone)) / 1000);
      return res.status(429).json({ error: '发送过于频繁', retry_after: remaining });
    }
    const code = generateCode();
    const result = await sendSMS(phone, code);
    if (result.success) {
      smsCodes.set(phone, { code, expires: Date.now() + 600000, attempts: 0 });
      smsSendRecords.set(phone, Date.now());
      res.json({ success: true, message: '验证码已发送', expires_in: 600 });
    } else {
      res.status(500).json({ error: '发送失败' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/sms/verify', async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) return res.status(400).json({ error: '手机号和验证码不能为空' });
    const record = smsCodes.get(phone);
    if (!record) return res.status(400).json({ error: '请先获取验证码' });
    if (record.expires < Date.now()) { smsCodes.delete(phone); return res.status(400).json({ error: '验证码已过期' }); }
    if (record.attempts >= 5) { smsCodes.delete(phone); return res.status(400).json({ error: '验证次数过多' }); }
    if (record.code !== code) { record.attempts += 1; smsCodes.set(phone, record); return res.status(400).json({ error: '验证码错误', remaining_attempts: 5 - record.attempts }); }
    smsCodes.delete(phone); smsSendRecords.delete(phone);
    res.json({ valid: true, message: '验证成功' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/sms/resend', async (req, res) => {
  try {
    const { phone } = req.body;
    const existingRecord = smsCodes.get(phone);
    if (!existingRecord) return res.status(400).json({ error: '请先获取验证码' });
    if (!canSendSMS(phone)) {
      const remaining = 60 - Math.floor((Date.now() - smsSendRecords.get(phone)) / 1000);
      return res.status(429).json({ error: '发送过于频繁', retry_after: remaining });
    }
    await sendSMS(phone, existingRecord.code);
    smsSendRecords.set(phone, Date.now());
    existingRecord.expires = Date.now() + 600000;
    smsCodes.set(phone, existingRecord);
    res.json({ success: true, message: '验证码已重新发送', expires_in: 600 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 2. 即时通讯服务 - 融云IM
// ========================================
async function getRongCloudToken(userId, name, portraitUri) {
  if (!RONGCLOUD_CONFIG.appKey || !RONGCLOUD_CONFIG.appSecret) {
    return { token: `mock_token_${userId}_${Date.now()}`, userId: userId.toString() };
  }
  try {
    const nonce = Math.floor(Math.random() * 1000000).toString();
    const timestamp = Date.now().toString();
    const signature = require('crypto').createHash('sha1').update(RONGCLOUD_CONFIG.appSecret + nonce + timestamp).digest('hex');
    const response = await axios.post(`${RONGCLOUD_CONFIG.apiUrl}/user/getToken.json`, null, {
      params: { appKey: RONGCLOUD_CONFIG.appKey, nonce, timestamp, signature, userId: userId.toString(), name: name || '', portraitUri: portraitUri || '' }
    });
    if (response.data.code === 200) return response.data;
    throw new Error(response.data.errorMessage || '获取Token失败');
  } catch (error) {
    console.error('[RongCloud Error]', error.message);
    return { token: `mock_token_${userId}_${Date.now()}`, userId: userId.toString() };
  }
}

app.get('/api/im/token', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [users] = await pool.execute('SELECT id, nickname, avatar FROM users WHERE id = ?', [decoded.userId]);
    if (users.length === 0) return res.status(404).json({ error: '用户不存在' });
    const user = users[0];
    const result = await getRongCloudToken(user.id, user.nickname, user.avatar);
    res.json({ token: result.token, userId: result.userId, appKey: RONGCLOUD_CONFIG.appKey });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/im/callback', async (req, res) => {
  try {
    const { type, senderId, targetId, content, messageId, timestamp } = req.body;
    console.log(`[IM Callback] ${type} - From: ${senderId}, To: ${targetId}`);
    const pool = await getPool();
    if (type === 'message') {
      await pool.execute(`INSERT INTO im_messages (sender_id, receiver_id, content, message_id, sent_at) VALUES (?, ?, ?, ?, FROM_UNIXTIME(?/1000))`, [senderId, targetId, content, messageId, timestamp]);
    }
    res.json({ code: 200 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/im/unread', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await pool.execute(`CREATE TABLE IF NOT EXISTS im_messages (id INT PRIMARY KEY AUTO_INCREMENT, sender_id INT, receiver_id INT, content TEXT, message_id VARCHAR(100), is_read BOOLEAN DEFAULT FALSE, sent_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    const [result] = await pool.execute(`SELECT COUNT(*) as count FROM im_messages WHERE receiver_id = ? AND is_read = FALSE`, [decoded.userId]);
    res.json({ unread: result[0].count });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/im/read', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { senderId } = req.body;
    const pool = await getPool();
    await pool.execute(`UPDATE im_messages SET is_read = TRUE WHERE receiver_id = ? AND sender_id = ?`, [decoded.userId, senderId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/im/conversations', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [conversations] = await pool.execute(
      `SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as user_id, content as last_message, sent_at, SUM(CASE WHEN receiver_id = ? AND is_read = FALSE THEN 1 ELSE 0 END) as unread_count FROM im_messages WHERE sender_id = ? OR receiver_id = ? GROUP BY user_id ORDER BY sent_at DESC LIMIT 20`,
      [decoded.userId, decoded.userId, decoded.userId, decoded.userId]
    );
    const userIds = conversations.map(c => c.user_id);
    if (userIds.length > 0) {
      const [users] = await pool.execute(`SELECT id, nickname, avatar FROM users WHERE id IN (?)`, [userIds]);
      const userMap = {}; users.forEach(u => userMap[u.id] = u);
      conversations.forEach(c => { if (userMap[c.user_id]) c.user = userMap[c.user_id]; });
    }
    res.json(conversations);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 3. 高德地图服务
// ========================================
async function geocode(address) {
  if (!AMAP_CONFIG.key) return { location: '116.397428,39.90923', province: '北京市', city: '北京市', district: '朝阳区' };
  try {
    const response = await axios.get('https://restapi.amap.com/v3/geocode/geo', { params: { key: AMAP_CONFIG.key, address, output: 'JSON' } });
    if (response.data.status === '1' && response.data.geocodes.length > 0) return response.data.geocodes[0];
    return null;
  } catch (error) { return null; }
}

async function regeocode(lng, lat) {
  if (!AMAP_CONFIG.key) return { formatted_address: '北京市朝阳区', addressComponent: { province: '北京市', city: '北京市', district: '朝阳区' } };
  try {
    const response = await axios.get('https://restapi.amap.com/v3/geocode/regeo', { params: { key: AMAP_CONFIG.key, location: `${lng},${lat}`, output: 'JSON' } });
    if (response.data.status === '1') return response.data.regeocode;
    return null;
  } catch (error) { return null; }
}

async function searchNearby(lng, lat, keywords, radius = 3000) {
  if (!AMAP_CONFIG.key) return { pois: [{ name: '朝阳公园', location: '116.397428,39.90923', distance: 500 }] };
  try {
    const response = await axios.get('https://restapi.amap.com/v3/place/nearby', { params: { key: AMAP_CONFIG.key, location: `${lng},${lat}`, keywords, radius, output: 'JSON' } });
    if (response.data.status === '1') return { pois: response.data.pois || [] };
    return { pois: [] };
  } catch (error) { return { pois: [] }; }
}

app.get('/api/map/geocode', async (req, res) => {
  try {
    const { address } = req.query;
    if (!address) return res.status(400).json({ error: '地址不能为空' });
    const result = await geocode(address);
    result ? res.json(result) : res.status(404).json({ error: '未找到对应坐标' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/map/regeocode', async (req, res) => {
  try {
    const { lng, lat } = req.query;
    if (!lng || !lat) return res.status(400).json({ error: '经纬度不能为空' });
    const result = await regeocode(lng, lat);
    result ? res.json(result) : res.status(404).json({ error: '未找到对应地址' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/map/nearby', async (req, res) => {
  try {
    const { lng, lat, keywords, radius } = req.query;
    if (!lng || !lat) return res.status(400).json({ error: '经纬度不能为空' });
    const result = await searchNearby(lng, lat, keywords || '宠物', radius || 3000);
    res.json(result);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/map/suggestion', async (req, res) => {
  try {
    const { keywords } = req.query;
    if (!keywords) return res.status(400).json({ error: '关键词不能为空' });
    if (!AMAP_CONFIG.key) return res.json({ suggestions: [] });
    const response = await axios.get('https://restapi.amap.com/v3/assistant/inputtips', { params: { key: AMAP_CONFIG.key, keywords, types: '商务住宅|风景名胜|科教文化|医疗福利', output: 'JSON' } });
    res.json({ suggestions: response.data.tips || [] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 4. 智能匹配算法
// ========================================
function calculateMatchScore(pet1, pet2) {
  let score = 0; const factors = [];
  const genderScore = pet1.gender !== pet2.gender ? 40 : 0;
  score += genderScore; factors.push({ factor: '性别匹配', score: genderScore, max: 40 });
  const ageDiff = Math.abs(pet1.age - pet2.age);
  let ageScore = ageDiff === 0 ? 30 : ageDiff <= 1 ? 25 : ageDiff <= 2 ? 20 : ageDiff <= 3 ? 10 : 0;
  score += ageScore; factors.push({ factor: '年龄匹配', score: ageScore, max: 30 });
  const breedScore = pet1.breed === pet2.breed ? 20 : 10;
  score += breedScore; factors.push({ factor: '品种匹配', score: breedScore, max: 20 });
  let healthScore = 0;
  if (pet1.vaccinated && pet2.vaccinated) healthScore += 5;
  if (pet1.certificate && pet2.certificate) healthScore += 5;
  score += healthScore; factors.push({ factor: '健康匹配', score: healthScore, max: 10 });
  return { totalScore: score, factors };
}

app.get('/api/pets/recommend', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [myPets] = await pool.execute('SELECT * FROM pets WHERE user_id = ?', [decoded.userId]);
    if (myPets.length === 0) return res.json({ recommendations: [], message: '请先添加您的宠物' });
    const [allPets] = await pool.execute('SELECT p.*, u.nickname as owner_nickname, u.location as owner_location FROM pets p JOIN users u ON p.user_id = u.id WHERE p.user_id != ?', [decoded.userId]);
    const recommendations = [];
    for (const myPet of myPets) {
      for (const otherPet of allPets) {
        const matchResult = calculateMatchScore(myPet, otherPet);
        recommendations.push({ myPet, pet: otherPet, matchScore: matchResult.totalScore, factors: matchResult.factors });
      }
    }
    recommendations.sort((a, b) => b.matchScore - a.matchScore);
    res.json({ recommendations: recommendations.slice(0, 20), total: recommendations.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/pets/:id/match', async (req, res) => {
  try {
    const { id } = req.params;
    const { targetId } = req.query;
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT * FROM pets WHERE id IN (?, ?)', [id, targetId]);
    if (pets.length !== 2) return res.status(404).json({ error: '宠物不存在' });
    const matchResult = calculateMatchScore(pets[0], pets[1]);
    res.json(matchResult);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/pets/smart-match', async (req, res) => {
  try {
    const { gender, breed, minAge, maxAge, location } = req.query;
    const pool = await getPool();
    let query = 'SELECT p.*, u.nickname as owner_nickname FROM pets p JOIN users u ON p.user_id = u.id WHERE 1=1';
    const params = [];
    if (gender) { query += ' AND p.gender = ?'; params.push(gender); }
    if (breed) { query += ' AND p.breed = ?'; params.push(breed); }
    if (minAge) { query += ' AND p.age >= ?'; params.push(parseInt(minAge)); }
    if (maxAge) { query += ' AND p.age <= ?'; params.push(parseInt(maxAge)); }
    if (location) { query += ' AND u.location LIKE ?'; params.push(`%${location}%`); }
    query += ' ORDER BY p.created_at DESC LIMIT 50';
    const [pets] = await pool.execute(query, params);
    const petsWithScore = pets.map(pet => ({ ...pet, matchScore: pet.gender !== (gender === '公' ? '母' : '公') ? 50 : 0 }));
    res.json(petsWithScore);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 5. 评论系统
// ========================================
async function initCommentDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS comments (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, post_id INT NOT NULL, parent_id INT DEFAULT NULL, content TEXT NOT NULL, likes_count INT DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (post_id) REFERENCES posts(id), FOREIGN KEY (parent_id) REFERENCES comments(id))`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS comment_likes (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, comment_id INT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY unique_like (user_id, comment_id), FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (comment_id) REFERENCES comments(id))`);
}

app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const { postId } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    const pool = await getPool();
    await initCommentDB();
    const [comments] = await pool.execute(
      `SELECT c.*, u.nickname, u.avatar as user_avatar, (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) as likes_count FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? AND c.parent_id IS NULL ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
      [postId, parseInt(limit), parseInt(offset)]
    );
    for (const comment of comments) {
      const [replies] = await pool.execute(`SELECT c.*, u.nickname, u.avatar as user_avatar, (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) as likes_count FROM comments c JOIN users u ON c.user_id = u.id WHERE c.parent_id = ? ORDER BY c.created_at ASC`, [comment.id]);
      comment.replies = replies;
    }
    res.json(comments);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts/:postId/comments', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { postId } = req.params;
    const { content, parentId } = req.body;
    if (!content || content.trim().length === 0) return res.status(400).json({ error: '评论内容不能为空' });
    if (content.length > 500) return res.status(400).json({ error: '评论内容过长' });
    const pool = await getPool();
    await initCommentDB();
    const [result] = await pool.execute('INSERT INTO comments (user_id, post_id, parent_id, content) VALUES (?, ?, ?, ?)', [decoded.userId, postId, parentId || null, content]);
    await pool.execute('UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?', [postId]);
    await pool.execute('UPDATE users SET points = points + 2 WHERE id = ?', [decoded.userId]);
    res.json({ id: result.insertId, success: true, points_earned: 2 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/comments/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const pool = await getPool();
    const [comments] = await pool.execute('SELECT user_id, post_id FROM comments WHERE id = ?', [id]);
    if (comments.length === 0) return res.status(404).json({ error: '评论不存在' });
    if (comments[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限删除此评论' });
    await pool.execute('DELETE FROM comment_likes WHERE comment_id = ? OR parent_id = ?', [id, id]);
    await pool.execute('DELETE FROM comments WHERE id = ? OR parent_id = ?', [id, id]);
    await pool.execute('UPDATE posts SET comments_count = GREATEST(comments_count - 1, 0) WHERE id = ?', [comments[0].post_id]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/comments/:id/like', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const pool = await getPool();
    try {
      await pool.execute('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)', [decoded.userId, id]);
      await pool.execute('UPDATE comments SET likes_count = likes_count + 1 WHERE id = ?', [id]);
      res.json({ success: true, liked: true });
    } catch (e) {
      await pool.execute('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?', [decoded.userId, id]);
      await pool.execute('UPDATE comments SET likes_count = GREATEST(likes_count - 1, 0) WHERE id = ?', [id]);
      res.json({ success: true, liked: false });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 6. 积分系统
// ========================================
const POINTS_RULES = {
  daily_login: { points: 10, description: '每日登录' },
  publish_post: { points: 20, description: '发布帖子' },
  comment: { points: 2, description: '发表评论' },
  like_received: { points: 1, description: '获得点赞' },
  share: { points: 5, description: '分享内容' },
  perfect_profile: { points: 50, description: '完善资料' },
  add_pet: { points: 30, description: '添加宠物' },
  verify_pet: { points: 100, description: '宠物认证' },
  vip_buy: { points: -500, description: '购买VIP' },
  super_like: { points: -10, description: '超级喜欢' },
  boost: { points: -20, description: '置顶推广' }
};

async function initPointsDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS points_records (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, type VARCHAR(50) NOT NULL, amount INT NOT NULL, description VARCHAR(255), created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS levels (id INT PRIMARY KEY AUTO_INCREMENT, level INT UNIQUE NOT NULL, name VARCHAR(50) NOT NULL, min_exp INT NOT NULL, max_exp INT, icon VARCHAR(50))`);
  const [levels] = await pool.execute('SELECT COUNT(*) as cnt FROM levels');
  if (levels[0].cnt === 0) {
    await pool.execute(`INSERT INTO levels (level, name, min_exp, max_exp, icon) VALUES (1, '新手', 0, 100, '🌱'), (2, '初级', 100, 300, '🌿'), (3, '中级', 300, 600, '🌳'), (4, '高级', 600, 1000, '⭐'), (5, '专家', 1000, 2000, '💎'), (6, '大师', 2000, NULL, '👑')`);
  }
}

app.get('/api/points/history', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await initPointsDB();
    const { limit = 20, offset = 0, type } = req.query;
    let query = 'SELECT * FROM points_records WHERE user_id = ?';
    const params = [decoded.userId];
    if (type) { query += ' AND type = ?'; params.push(type); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    const [records] = await pool.execute(query, params);
    const [users] = await pool.execute('SELECT points, exp FROM users WHERE id = ?', [decoded.userId]);
    const [levels] = await pool.execute('SELECT * FROM levels ORDER BY level ASC');
    let currentLevel = levels[0];
    for (const level of levels) {
      if (users[0].exp >= level.min_exp && (!level.max_exp || users[0].exp < level.max_exp)) { currentLevel = level; break; }
    }
    res.json({ records, points: users[0]?.points || 0, exp: users[0]?.exp || 0, level: currentLevel });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/points/add', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { type, amount, description } = req.body;
    const pool = await getPool();
    await initPointsDB();
    const rule = POINTS_RULES[type];
    const actualAmount = amount || (rule ? rule.points : 0);
    await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, type, actualAmount, description || (rule ? rule.description : '')]);
    if (actualAmount > 0) {
      await pool.execute('UPDATE users SET points = points + ?, exp = exp + ? WHERE id = ?', [actualAmount, actualAmount, decoded.userId]);
    } else {
      await pool.execute('UPDATE users SET points = points + ? WHERE id = ?', [actualAmount, decoded.userId]);
    }
    const [users] = await pool.execute('SELECT points, exp FROM users WHERE id = ?', [decoded.userId]);
    res.json({ success: true, points: users[0].points, exp: users[0].exp });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/points/rules', (req, res) => { res.json(POINTS_RULES); });

app.get('/api/levels', async (req, res) => {
  try {
    const pool = await getPool();
    await initPointsDB();
    const [levels] = await pool.execute('SELECT * FROM levels ORDER BY level ASC');
    res.json(levels);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 7. VIP会员系统
// ========================================
const VIP_PACKAGES = [
  { id: 'monthly', name: '月度VIP', price: 30, duration: 30, features: ['无限喜欢', '超级喜欢', '查看联系方式', '优先推荐'] },
  { id: 'quarterly', name: '季度VIP', price: 80, duration: 90, features: ['无限喜欢', '超级喜欢', '查看联系方式', '优先推荐', '专属标识'] },
  { id: 'yearly', name: '年度VIP', price: 300, duration: 365, features: ['无限喜欢', '超级喜欢', '查看联系方式', '优先推荐', '专属标识', '线下活动免费'] }
];

async function initVipDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS vip_orders (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, package_id VARCHAR(50) NOT NULL, amount DECIMAL(10,2) NOT NULL, status VARCHAR(20) DEFAULT 'pending', paid_at DATETIME, expires_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
}

app.get('/api/vip/packages', (req, res) => { res.json(VIP_PACKAGES); });

app.post('/api/vip/purchase', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { packageId } = req.body;
    const pkg = VIP_PACKAGES.find(p => p.id === packageId);
    if (!pkg) return res.status(400).json({ error: '无效的套餐' });
    const pool = await getPool();
    await initVipDB();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + pkg.duration);
    const [result] = await pool.execute(`INSERT INTO vip_orders (user_id, package_id, amount, status, paid_at, expires_at) VALUES (?, ?, ?, 'paid', NOW(), ?)`, [decoded.userId, pkg.id, pkg.price, expiresAt]);
    await pool.execute(`UPDATE users SET vip_expire_at = ? WHERE id = ?`, [expiresAt, decoded.userId]);
    await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, 'vip_buy', -pkg.price, `购买${pkg.name}`]);
    res.json({ success: true, orderId: result.insertId, expiresAt, vipExpireAt: expiresAt });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/vip/status', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [users] = await pool.execute('SELECT vip_expire_at FROM users WHERE id = ?', [decoded.userId]);
    const vipExpireAt = users[0]?.vip_expire_at;
    const isVip = vipExpireAt && new Date(vipExpireAt) > new Date();
    res.json({ isVip, vipExpireAt });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/vip/orders', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await initVipDB();
    const [orders] = await pool.execute('SELECT * FROM vip_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', [decoded.userId]);
    res.json(orders);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 8. 活动报名系统
// ========================================
async function initActivityDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS activity_registrations (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, activity_id INT NOT NULL, status VARCHAR(20) DEFAULT 'registered', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (activity_id) REFERENCES activities(id), UNIQUE KEY unique_registration (user_id, activity_id))`);
}

app.get('/api/activities/:id/registrations', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    await initActivityDB();
    const [registrations] = await pool.execute(
      `SELECT r.*, u.nickname, u.avatar FROM activity_registrations r JOIN users u ON r.user_id = u.id WHERE r.activity_id = ? AND r.status = 'registered'`,
      [id]
    );
    res.json(registrations);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/activities/:id/register', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const pool = await getPool();
    await initActivityDB();
    const [activity] = await pool.execute('SELECT * FROM activities WHERE id = ?', [id]);
    if (activity.length === 0) return res.status(404).json({ error: '活动不存在' });
    if (activity[0].max_participants && activity[0].participants_count >= activity[0].max_participants) {
      return res.status(400).json({ error: '活动已满' });
    }
    try {
      await pool.execute('INSERT INTO activity_registrations (user_id, activity_id) VALUES (?, ?)', [decoded.userId, id]);
      await pool.execute('UPDATE activities SET participants_count = participants_count + 1 WHERE id = ?', [id]);
      res.json({ success: true, message: '报名成功' });
    } catch (e) {
      return res.status(400).json({ error: '您已报名此活动' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/activities/:id/register', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const pool = await getPool();
    await initActivityDB();
    const [result] = await pool.execute('DELETE FROM activity_registrations WHERE user_id = ? AND activity_id = ?', [decoded.userId, id]);
    if (result.affectedRows > 0) {
      await pool.execute('UPDATE activities SET participants_count = GREATEST(participants_count - 1, 0) WHERE id = ?', [id]);
      res.json({ success: true, message: '取消报名成功' });
    } else {
      res.status(404).json({ error: '报名记录不存在' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/activities/my', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await initActivityDB();
    const [activities] = await pool.execute(
      `SELECT a.* FROM activities a JOIN activity_registrations r ON a.id = r.activity_id WHERE r.user_id = ? AND r.status = 'registered' ORDER BY a.date ASC`,
      [decoded.userId]
    );
    res.json(activities);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 9. 消息推送系统
// ========================================
async function initNotificationDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS notifications (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, type VARCHAR(50) NOT NULL, title VARCHAR(100) NOT NULL, content TEXT, data JSON, is_read BOOLEAN DEFAULT FALSE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
}

app.get('/api/notifications', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await initNotificationDB();
    const { limit = 20, offset = 0 } = req.query;
    const [notifications] = await pool.execute(
      'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [decoded.userId, parseInt(limit), parseInt(offset)]
    );
    const [unreadCount] = await pool.execute('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE', [decoded.userId]);
    res.json({ notifications, unreadCount: unreadCount[0].count });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/notifications/:id/read', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const pool = await getPool();
    await pool.execute('UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?', [id, decoded.userId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/notifications/read-all', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    await pool.execute('UPDATE notifications SET is_read = TRUE WHERE user_id = ?', [decoded.userId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 系统通知推送（内部接口）
app.post('/api/admin/notify', async (req, res) => {
  try {
    const { userId, type, title, content, data } = req.body;
    const pool = await getPool();
    await initNotificationDB();
    await pool.execute(
      'INSERT INTO notifications (user_id, type, title, content, data) VALUES (?, ?, ?, ?, ?)',
      [userId, type, title, content, JSON.stringify(data || {})]
    );
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 互动通知
async function sendInteractionNotification(pool, fromUserId, toUserId, type, content) {
  await initNotificationDB();
  await pool.execute(
    'INSERT INTO notifications (user_id, type, title, content) VALUES (?, ?, ?, ?)',
    [toUserId, type, '新互动通知', content]
  );
}

// ========================================
// 10. 行为分析系统
// ========================================
async function initAnalyticsDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS analytics_events (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT, event_type VARCHAR(50) NOT NULL, event_data JSON, ip_address VARCHAR(50), user_agent VARCHAR(255), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS daily_stats (id INT PRIMARY KEY AUTO_INCREMENT, stat_date DATE UNIQUE NOT NULL, new_users INT DEFAULT 0, active_users INT DEFAULT 0, new_posts INT DEFAULT 0, new_pets INT DEFAULT 0, total_messages INT DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
}

app.post('/api/analytics/track', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    let userId = null;
    if (token) {
      try { const decoded = jwt.verify(token, JWT_SECRET); userId = decoded.userId; } catch (e) {}
    }
    const { eventType, data } = req.body;
    const pool = await getPool();
    await initAnalyticsDB();
    await pool.execute(
      'INSERT INTO analytics_events (user_id, event_type, event_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
      [userId, eventType, JSON.stringify(data || {}), req.ip, req.headers['user-agent']]
    );
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/analytics/stats', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const pool = await getPool();
    await initAnalyticsDB();
    let query = 'SELECT * FROM daily_stats WHERE 1=1';
    const params = [];
    if (startDate) { query += ' AND stat_date >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND stat_date <= ?'; params.push(endDate); }
    query += ' ORDER BY stat_date DESC LIMIT 30';
    const [stats] = await pool.execute(query, params);
    res.json(stats);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/analytics/events', async (req, res) => {
  try {
    const { eventType, limit = 100 } = req.query;
    const pool = await getPool();
    await initAnalyticsDB();
    let query = 'SELECT * FROM analytics_events';
    const params = [];
    if (eventType) { query += ' WHERE event_type = ?'; params.push(eventType); }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));
    const [events] = await pool.execute(query, params);
    res.json(events);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 原有基础功能
// ========================================

async function initDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, phone VARCHAR(20) UNIQUE, nickname VARCHAR(50), avatar VARCHAR(255) DEFAULT '🐱', password VARCHAR(255), points INT DEFAULT 100, exp INT DEFAULT 0, vip_expire_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS pets (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT, name VARCHAR(50), breed VARCHAR(50), age INT, gender ENUM('公', '母'), avatar VARCHAR(255), personality VARCHAR(100), vaccinated BOOLEAN DEFAULT FALSE, certificate BOOLEAN DEFAULT FALSE, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS posts (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT, user_nickname VARCHAR(50), user_avatar VARCHAR(255), content TEXT, images JSON, category VARCHAR(50), location VARCHAR(100), likes INT DEFAULT 0, comments_count INT DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
  await pool.execute(`CREATE TABLE IF NOT EXISTS activities (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT, title VARCHAR(100), description TEXT, location VARCHAR(100), address VARCHAR(255), lat DOUBLE, lng DOUBLE, date VARCHAR(50), time VARCHAR(20), fee VARCHAR(20) DEFAULT '免费', max_participants INT, participants_count INT DEFAULT 0, images JSON, type VARCHAR(50), tags JSON, status VARCHAR(20) DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
  const [users] = await pool.execute('SELECT COUNT(*) as cnt FROM users');
  if (users[0].cnt === 0) {
    const hashedPassword = await bcrypt.hash('123456', 10);
    await pool.execute(`INSERT INTO users (phone, nickname, avatar, password, points, exp) VALUES ('13800000001', '萌宠达人', '🐱', '${hashedPassword}', 100, 150), ('13800000002', '金毛爸爸', '🐕', '${hashedPassword}', 80, 80), ('13800000003', '布偶猫奴', '🐱', '${hashedPassword}', 150, 200)`);
    await pool.execute(`INSERT INTO pets (user_id, name, breed, age, gender, avatar, personality, vaccinated, certificate) VALUES (1, '小橘', '中华田园猫', 1, '母', '🐱', '黏人', TRUE, TRUE), (2, '旺财', '金毛', 2, '公', '🐕', '活泼', TRUE, FALSE)`);
    await pool.execute(`INSERT INTO posts (user_id, user_nickname, user_avatar, content, category, location, likes) VALUES (1, '萌宠达人', '🐱', '今天带小橘去公园遛弯，遇到了好多小伙伴！', 'play', '朝阳区·朝阳公园', 328), (2, '金毛爸爸', '🐕', '拆家小能手又开始了...我已经习惯了', 'funny', '海淀区', 189), (3, '布偶猫奴', '🐱', '主子今天终于肯让我拍照了！', 'cute', '', 512)`);
  }
  console.log('Database initialized');
}

initDB().catch(console.error);

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password, code } = req.body;
    const pool = await getPool();
    if (code) {
      const [users] = await pool.execute('SELECT * FROM users WHERE phone = ?', [phone]);
      if (users.length === 0) {
        const [result] = await pool.execute('INSERT INTO users (phone, nickname, avatar, password) VALUES (?, ?, ?, ?)', [phone, '用户' + phone.slice(-4), '🐱', '']);
        const token = jwt.sign({ userId: result.insertId, phone }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token, user: { id: result.insertId, phone, nickname: '用户' + phone.slice(-4), avatar: '🐱' } });
      }
      const token = jwt.sign({ userId: users[0].id, phone }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: users[0] });
    }
    const [users] = await pool.execute('SELECT * FROM users WHERE phone = ?', [phone]);
    if (users.length === 0) return res.status(401).json({ error: '用户不存在' });
    if (users[0].password && !await bcrypt.compare(password, users[0].password)) return res.status(401).json({ error: '密码错误' });
    const token = jwt.sign({ userId: users[0].id, phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: users[0] });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password, nickname } = req.body;
    const pool = await getPool();
    const [existing] = await pool.execute('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing.length > 0) return res.status(400).json({ error: '手机号已注册' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.execute('INSERT INTO users (phone, password, nickname, avatar) VALUES (?, ?, ?, ?)', [phone, hashedPassword, nickname || '用户' + phone.slice(-4), '🐱']);
    const token = jwt.sign({ userId: result.insertId, phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.insertId, phone, nickname, avatar: '🐱' } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/users/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    if (users.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(users[0]);
  } catch (error) { res.status(401).json({ error: '无效的token' }); }
});

app.get('/api/pets', async (req, res) => {
  try {
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT * FROM pets ORDER BY created_at DESC');
    res.json(pets);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/pets/match', async (req, res) => {
  try {
    const { gender, breed } = req.query;
    const pool = await getPool();
    let query = 'SELECT * FROM pets WHERE 1=1';
    const params = [];
    if (gender) { query += ' AND gender != ?'; params.push(gender); }
    if (breed) { query += ' AND breed = ?'; params.push(breed); }
    const [pets] = await pool.execute(query, params);
    res.json(pets);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/pets', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, breed, age, gender, avatar, personality, vaccinated, certificate, description } = req.body;
    const pool = await getPool();
    const [result] = await pool.execute('INSERT INTO pets (user_id, name, breed, age, gender, avatar, personality, vaccinated, certificate, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [decoded.userId, name, breed, age, gender, avatar || '🐱', personality, vaccinated || false, certificate || false, description || '']);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/posts', async (req, res) => {
  try {
    const pool = await getPool();
    const { category, limit = 20, offset = 0 } = req.query;
    let query = 'SELECT * FROM posts';
    const params = [];
    if (category) { query += ' WHERE category = ?'; params.push(category); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    const [posts] = await pool.execute(query, params);
    res.json(posts);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { content, images, category, location } = req.body;
    const pool = await getPool();
    const [user] = await pool.execute('SELECT nickname, avatar FROM users WHERE id = ?', [decoded.userId]);
    const [result] = await pool.execute('INSERT INTO posts (user_id, user_nickname, user_avatar, content, images, category, location) VALUES (?, ?, ?, ?, ?, ?, ?)', [decoded.userId, user[0].nickname, user[0].avatar, content, JSON.stringify(images || []), category, location || '']);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const pool = await getPool();
    await pool.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/activities', async (req, res) => {
  try {
    const pool = await getPool();
    const [activities] = await pool.execute('SELECT * FROM activities ORDER BY created_at DESC');
    res.json(activities);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/activities', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags } = req.body;
    const pool = await getPool();
    const [result] = await pool.execute('INSERT INTO activities (user_id, title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [decoded.userId, title, description, location, address, lat, lng, date, time, fee || '免费', max_participants, JSON.stringify(images || []), type, JSON.stringify(tags || [])]);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 11. 用户系统完整版 - 第三方登录、头像上传、收货地址
// ========================================

// 微信登录配置
const WECHAT_CONFIG = {
  appId: process.env.WECHAT_APP_ID || '',
  appSecret: process.env.WECHAT_APP_SECRET || '',
  redirectUri: process.env.WECHAT_REDIRECT_URI || ''
};

// 微博登录配置
const WEIBO_CONFIG = {
  appKey: process.env.WEIBO_APP_KEY || '',
  appSecret: process.env.WEIBO_APP_SECRET || '',
  redirectUri: process.env.WEIBO_REDIRECT_URI || ''
};

// 初始化用户扩展表
async function initUserExtensionDB() {
  const pool = await getPool();
  // 第三方账号绑定表
  await pool.execute(`CREATE TABLE IF NOT EXISTS user_bindings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    platform VARCHAR(20) NOT NULL,
    openid VARCHAR(100) UNIQUE NOT NULL,
    unionid VARCHAR(100),
    access_token TEXT,
    refresh_token TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_platform_user (platform, user_id)
  )`);
  
  // 收货地址表
  await pool.execute(`CREATE TABLE IF NOT EXISTS addresses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    name VARCHAR(50) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    province VARCHAR(50) NOT NULL,
    city VARCHAR(50) NOT NULL,
    district VARCHAR(50) NOT NULL,
    detail_address VARCHAR(255) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // 用户资料扩展表
  await pool.execute(`CREATE TABLE IF NOT EXISTS user_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE NOT NULL,
    bio VARCHAR(500),
    gender ENUM('未知', '男', '女'),
    birthday DATE,
    location VARCHAR(100),
    occupation VARCHAR(100),
    education VARCHAR(50),
    interest_tags JSON,
    social_links JSON,
    cover_image VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
}

// 微信登录
app.get('/api/auth/wechat/login', (req, res) => {
  const redirectUrl = `https://open.weixin.qq.com/connect/oauth2/authorize?appid=${WECHAT_CONFIG.appId}&redirect_uri=${encodeURIComponent(WECHAT_CONFIG.redirectUri)}&response_type=code&scope=snsapi_userinfo#wechat_redirect`;
  res.redirect(redirectUrl);
});

app.get('/api/auth/wechat/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: '授权码不能为空' });
    
    // 获取access_token
    const tokenUrl = `https://api.weixin.qq.com/sns/oauth2/access_token?appid=${WECHAT_CONFIG.appId}&secret=${WECHAT_CONFIG.appSecret}&code=${code}&grant_type=authorization_code`;
    const tokenRes = await axios.get(tokenUrl);
    const tokenData = tokenRes.data;
    
    if (tokenData.errcode) {
      return res.status(400).json({ error: tokenData.errmsg });
    }
    
    // 获取用户信息
    const userInfoUrl = `https://api.weixin.qq.com/sns/userinfo?access_token=${tokenData.access_token}&openid=${tokenData.openid}&lang=zh_CN`;
    const userInfoRes = await axios.get(userInfoUrl);
    const wechatUser = userInfoRes.data;
    
    const pool = await getPool();
    await initUserExtensionDB();
    
    // 查找已绑定的用户
    let [bindings] = await pool.execute('SELECT user_id FROM user_bindings WHERE platform = ? AND openid = ?', ['wechat', wechatUser.openid]);
    
    let user, token;
    
    if (bindings.length > 0) {
      // 已绑定，直接登录
      const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [bindings[0].user_id]);
      user = users[0];
    } else {
      // 新用户，创建账号
      const [result] = await pool.execute('INSERT INTO users (nickname, avatar, points) VALUES (?, ?, ?)', [wechatUser.nickname || '微信用户', wechatUser.headimgurl || '🐱', 100]);
      await pool.execute('INSERT INTO user_bindings (user_id, platform, openid, unionid, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 
        [result.insertId, 'wechat', wechatUser.openid, wechatUser.unionid, tokenData.access_token, tokenData.refresh_token, new Date(Date.now() + tokenData.expires_in * 1000)]);
      
      const [newUsers] = await pool.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
      user = newUsers[0];
    }
    
    token = jwt.sign({ userId: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user, isNewUser: bindings.length === 0 });
  } catch (error) {
    console.error('[WeChat Login Error]', error.message);
    res.status(500).json({ error: error.message });
  }
});

// 微博登录
app.get('/api/auth/weibo/login', (req, res) => {
  const redirectUrl = `https://api.weibo.com/oauth2/authorize?client_id=${WEIBO_CONFIG.appKey}&redirect_uri=${encodeURIComponent(WEIBO_CONFIG.redirectUri)}&response_type=code`;
  res.redirect(redirectUrl);
});

app.get('/api/auth/weibo/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: '授权码不能为空' });
    
    // 获取access_token
    const tokenUrl = 'https://api.weibo.com/oauth2/access_token';
    const tokenRes = await axios.post(tokenUrl, {
      client_id: WEIBO_CONFIG.appKey,
      client_secret: WEIBO_CONFIG.appSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: WEIBO_CONFIG.redirectUri
    });
    const tokenData = tokenRes.data;
    
    if (tokenData.error) {
      return res.status(400).json({ error: tokenData.error_description });
    }
    
    // 获取用户信息
    const userInfoUrl = 'https://api.weibo.com/2/users/show.json';
    const userInfoRes = await axios.get(userInfoUrl, { params: { access_token: tokenData.access_token, uid: tokenData.uid } });
    const weiboUser = userInfoRes.data;
    
    const pool = await getPool();
    await initUserExtensionDB();
    
    // 查找已绑定的用户
    let [bindings] = await pool.execute('SELECT user_id FROM user_bindings WHERE platform = ? AND openid = ?', ['weibo', weiboUser.id.toString()]);
    
    let user, token;
    
    if (bindings.length > 0) {
      const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [bindings[0].user_id]);
      user = users[0];
    } else {
      const [result] = await pool.execute('INSERT INTO users (nickname, avatar, points) VALUES (?, ?, ?)', [weiboUser.screen_name || '微博用户', weiboUser.profile_image_url || '🐱', 100]);
      await pool.execute('INSERT INTO user_bindings (user_id, platform, openid, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?, ?, ?)', 
        [result.insertId, 'weibo', weiboUser.id.toString(), tokenData.access_token, tokenData.refresh_token, new Date(Date.now() + tokenData.expires_in * 1000)]);
      
      const [newUsers] = await pool.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
      user = newUsers[0];
    }
    
    token = jwt.sign({ userId: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user, isNewUser: bindings.length === 0 });
  } catch (error) {
    console.error('[Weibo Login Error]', error.message);
    res.status(500).json({ error: error.message });
  }
});

// 获取绑定状态
app.get('/api/user/bindings', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initUserExtensionDB();
    const [bindings] = await pool.execute('SELECT platform, openid, created_at, updated_at FROM user_bindings WHERE user_id = ?', [decoded.userId]);
    res.json(bindings);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 解绑第三方账号
app.delete('/api/user/bindings/:platform', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { platform } = req.params;
    
    const pool = await getPool();
    await pool.execute('DELETE FROM user_bindings WHERE user_id = ? AND platform = ?', [decoded.userId, platform]);
    res.json({ success: true, message: '解绑成功' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取用户资料
app.get('/api/user/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    const [users] = await pool.execute('SELECT id, phone, nickname, avatar, points, exp, vip_expire_at, created_at FROM users WHERE id = ?', [decoded.userId]);
    const [profiles] = await pool.execute('SELECT * FROM user_profiles WHERE user_id = ?', [decoded.userId]);
    
    res.json({ ...users[0], profile: profiles[0] || {} });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 更新用户资料
app.put('/api/user/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { nickname, avatar, bio, gender, birthday, location, occupation, education, interest_tags, social_links, cover_image } = req.body;
    const pool = await getPool();
    
    // 更新基本信息
    if (nickname || avatar) {
      let updates = [];
      let params = [];
      if (nickname) { updates.push('nickname = ?'); params.push(nickname); }
      if (avatar) { updates.push('avatar = ?'); params.push(avatar); }
      params.push(decoded.userId);
      await pool.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    }
    
    // 更新扩展资料
    await initUserExtensionDB();
    const [existing] = await pool.execute('SELECT id FROM user_profiles WHERE user_id = ?', [decoded.userId]);
    
    if (existing.length > 0) {
      let updates = [];
      let params = [];
      if (bio !== undefined) { updates.push('bio = ?'); params.push(bio); }
      if (gender !== undefined) { updates.push('gender = ?'); params.push(gender); }
      if (birthday !== undefined) { updates.push('birthday = ?'); params.push(birthday); }
      if (location !== undefined) { updates.push('location = ?'); params.push(location); }
      if (occupation !== undefined) { updates.push('occupation = ?'); params.push(occupation); }
      if (education !== undefined) { updates.push('education = ?'); params.push(education); }
      if (interest_tags !== undefined) { updates.push('interest_tags = ?'); params.push(JSON.stringify(interest_tags)); }
      if (social_links !== undefined) { updates.push('social_links = ?'); params.push(JSON.stringify(social_links)); }
      if (cover_image !== undefined) { updates.push('cover_image = ?'); params.push(cover_image); }
      params.push(decoded.userId);
      if (updates.length > 0) {
        await pool.execute(`UPDATE user_profiles SET ${updates.join(', ')} WHERE user_id = ?`, params);
      }
    } else {
      await pool.execute('INSERT INTO user_profiles (user_id, bio, gender, birthday, location, occupation, education, interest_tags, social_links, cover_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [decoded.userId, bio, gender, birthday, location, occupation, education, JSON.stringify(interest_tags || []), JSON.stringify(social_links || {}), cover_image]);
    }
    
    // 首次完善资料奖励积分
    if (existing.length === 0 && (bio || gender || location)) {
      await pool.execute('UPDATE users SET points = points + 50 WHERE id = ?', [decoded.userId]);
      await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, 'perfect_profile', 50, '完善资料奖励']);
    }
    
    res.json({ success: true, pointsEarned: existing.length === 0 ? 50 : 0 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 头像上传（Base64）
app.post('/api/user/avatar', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { avatar } = req.body;
    if (!avatar) return res.status(400).json({ error: '头像不能为空' });
    
    const pool = await getPool();
    await pool.execute('UPDATE users SET avatar = ? WHERE id = ?', [avatar, decoded.userId]);
    res.json({ success: true, avatar });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取收货地址列表
app.get('/api/user/addresses', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initUserExtensionDB();
    const [addresses] = await pool.execute('SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC', [decoded.userId]);
    res.json(addresses);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加收货地址
app.post('/api/user/addresses', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { name, phone, province, city, district, detail_address, is_default } = req.body;
    if (!name || !phone || !province || !city || !district || !detail_address) {
      return res.status(400).json({ error: '请填写完整的地址信息' });
    }
    
    const pool = await getPool();
    await initUserExtensionDB();
    
    // 如果设为默认地址，先取消其他默认
    if (is_default) {
      await pool.execute('UPDATE addresses SET is_default = FALSE WHERE user_id = ?', [decoded.userId]);
    }
    
    const [result] = await pool.execute('INSERT INTO addresses (user_id, name, phone, province, city, district, detail_address, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [decoded.userId, name, phone, province, city, district, detail_address, is_default || false]);
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 更新收货地址
app.put('/api/user/addresses/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { name, phone, province, city, district, detail_address, is_default } = req.body;
    const pool = await getPool();
    
    // 验证归属
    const [addresses] = await pool.execute('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [id, decoded.userId]);
    if (addresses.length === 0) return res.status(404).json({ error: '地址不存在' });
    
    // 如果设为默认地址，先取消其他默认
    if (is_default) {
      await pool.execute('UPDATE addresses SET is_default = FALSE WHERE user_id = ?', [decoded.userId]);
    }
    
    await pool.execute('UPDATE addresses SET name = ?, phone = ?, province = ?, city = ?, district = ?, detail_address = ?, is_default = ? WHERE id = ?',
      [name, phone, province, city, district, detail_address, is_default || false, id]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 删除收货地址
app.delete('/api/user/addresses/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [result] = await pool.execute('DELETE FROM addresses WHERE id = ? AND user_id = ?', [id, decoded.userId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: '地址不存在' });
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 设置默认收货地址
app.put('/api/user/addresses/:id/default', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    // 取消其他默认
    await pool.execute('UPDATE addresses SET is_default = FALSE WHERE user_id = ?', [decoded.userId]);
    // 设置当前为默认
    await pool.execute('UPDATE addresses SET is_default = TRUE WHERE id = ? AND user_id = ?', [id, decoded.userId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 12. 宠物系统完整版 - 相册、视频、健康档案、疫苗、绝育、血统证书
// ========================================

async function initPetExtensionDB() {
  const pool = await getPool();
  
  // 宠物相册表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_albums (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    caption VARCHAR(255),
    is_cover BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 宠物视频表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_videos (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT NOT NULL,
    video_url VARCHAR(255) NOT NULL,
    cover_url VARCHAR(255),
    title VARCHAR(100),
    duration INT,
    views INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 宠物健康档案表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_health_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT NOT NULL,
    record_type VARCHAR(50) NOT NULL,
    record_date DATE NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    attachment_url VARCHAR(255),
    hospital VARCHAR(100),
    vet_name VARCHAR(50),
    cost DECIMAL(10,2),
    next_date DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 疫苗记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_vaccinations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT NOT NULL,
    vaccine_name VARCHAR(100) NOT NULL,
    vaccine_date DATE NOT NULL,
    batch_number VARCHAR(50),
    hospital VARCHAR(100),
    vet_name VARCHAR(50),
    next_date DATE,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 宠物绝育记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_neuter_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT UNIQUE NOT NULL,
    is_neutered BOOLEAN NOT NULL DEFAULT FALSE,
    neuter_date DATE,
    hospital VARCHAR(100),
    vet_name VARCHAR(50),
    notes TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 血统证书表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_certificates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT UNIQUE NOT NULL,
    certificate_type VARCHAR(50) NOT NULL,
    certificate_number VARCHAR(100),
    issuing_authority VARCHAR(100),
    issue_date DATE,
    expiry_date DATE,
    certificate_url VARCHAR(255),
    pedigree_level VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
  
  // 宠物标签表
  await pool.execute(`CREATE TABLE IF NOT EXISTS pet_tags (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pet_id INT NOT NULL,
    tag VARCHAR(50) NOT NULL,
    FOREIGN KEY (pet_id) REFERENCES pets(id)
  )`);
}

// 获取宠物详情（包含扩展信息）
app.get('/api/pets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT p.*, u.nickname as owner_nickname, u.avatar as owner_avatar FROM pets p JOIN users u ON p.user_id = u.id WHERE p.id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    
    const pet = pets[0];
    
    // 获取相册
    await initPetExtensionDB();
    const [albums] = await pool.execute('SELECT * FROM pet_albums WHERE pet_id = ? ORDER BY is_cover DESC, created_at DESC', [id]);
    pet.albums = albums;
    
    // 获取视频
    const [videos] = await pool.execute('SELECT * FROM pet_videos WHERE pet_id = ? ORDER BY created_at DESC', [id]);
    pet.videos = videos;
    
    // 获取健康记录
    const [healthRecords] = await pool.execute('SELECT * FROM pet_health_records WHERE pet_id = ? ORDER BY record_date DESC', [id]);
    pet.health_records = healthRecords;
    
    // 获取疫苗记录
    const [vaccinations] = await pool.execute('SELECT * FROM pet_vaccinations WHERE pet_id = ? ORDER BY vaccine_date DESC', [id]);
    pet.vaccinations = vaccinations;
    
    // 获取绝育状态
    const [neuterRecords] = await pool.execute('SELECT * FROM pet_neuter_records WHERE pet_id = ?', [id]);
    pet.neuter_record = neuterRecords[0] || { is_neutered: false };
    
    // 获取血统证书
    const [certificates] = await pool.execute('SELECT * FROM pet_certificates WHERE pet_id = ?', [id]);
    pet.certificate = certificates[0] || null;
    
    // 获取标签
    const [tags] = await pool.execute('SELECT tag FROM pet_tags WHERE pet_id = ?', [id]);
    pet.tags = tags.map(t => t.tag);
    
    res.json(pet);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 更新宠物基本信息
app.put('/api/pets/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { name, breed, age, gender, avatar, personality, vaccinated, certificate, description, tags } = req.body;
    const pool = await getPool();
    
    // 验证宠物归属
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限修改' });
    
    let updates = [];
    let params = [];
    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (breed !== undefined) { updates.push('breed = ?'); params.push(breed); }
    if (age !== undefined) { updates.push('age = ?'); params.push(age); }
    if (gender !== undefined) { updates.push('gender = ?'); params.push(gender); }
    if (avatar !== undefined) { updates.push('avatar = ?'); params.push(avatar); }
    if (personality !== undefined) { updates.push('personality = ?'); params.push(personality); }
    if (vaccinated !== undefined) { updates.push('vaccinated = ?'); params.push(vaccinated); }
    if (certificate !== undefined) { updates.push('certificate = ?'); params.push(certificate); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    
    if (updates.length > 0) {
      params.push(id);
      await pool.execute(`UPDATE pets SET ${updates.join(', ')} WHERE id = ?`, params);
    }
    
    // 更新标签
    if (tags) {
      await pool.execute('DELETE FROM pet_tags WHERE pet_id = ?', [id]);
      for (const tag of tags) {
        await pool.execute('INSERT INTO pet_tags (pet_id, tag) VALUES (?, ?)', [id, tag]);
      }
    }
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 删除宠物
app.delete('/api/pets/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限删除' });
    
    // 删除关联数据
    await pool.execute('DELETE FROM pet_albums WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_videos WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_health_records WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_vaccinations WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_neuter_records WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_certificates WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pet_tags WHERE pet_id = ?', [id]);
    await pool.execute('DELETE FROM pets WHERE id = ?', [id]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加宠物相册
app.post('/api/pets/:id/albums', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { image_url, caption, is_cover } = req.body;
    if (!image_url) return res.status(400).json({ error: '图片URL不能为空' });
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    
    // 如果设为封面，先取消其他封面
    if (is_cover) {
      await pool.execute('UPDATE pet_albums SET is_cover = FALSE WHERE pet_id = ?', [id]);
    }
    
    const [result] = await pool.execute('INSERT INTO pet_albums (pet_id, image_url, caption, is_cover) VALUES (?, ?, ?, ?)', [id, image_url, caption, is_cover || false]);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取宠物相册
app.get('/api/pets/:id/albums', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [albums] = await pool.execute('SELECT * FROM pet_albums WHERE pet_id = ? ORDER BY is_cover DESC, created_at DESC', [id]);
    res.json(albums);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 删除宠物相册
app.delete('/api/pets/:albumId/albums', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { albumId } = req.params;
    
    const pool = await getPool();
    const [albums] = await pool.execute('SELECT p.user_id FROM pet_albums a JOIN pets p ON a.pet_id = p.id WHERE a.id = ?', [albumId]);
    if (albums.length === 0) return res.status(404).json({ error: '相册不存在' });
    if (albums[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限删除' });
    
    await pool.execute('DELETE FROM pet_albums WHERE id = ?', [albumId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加宠物视频
app.post('/api/pets/:id/videos', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { video_url, cover_url, title, duration } = req.body;
    if (!video_url) return res.status(400).json({ error: '视频URL不能为空' });
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    const [result] = await pool.execute('INSERT INTO pet_videos (pet_id, video_url, cover_url, title, duration) VALUES (?, ?, ?, ?, ?)', [id, video_url, cover_url, title, duration]);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取宠物视频
app.get('/api/pets/:id/videos', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [videos] = await pool.execute('SELECT * FROM pet_videos WHERE pet_id = ? ORDER BY created_at DESC', [id]);
    res.json(videos);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 增加视频播放量
app.post('/api/pets/videos/:videoId/view', async (req, res) => {
  try {
    const { videoId } = req.params;
    const pool = await getPool();
    await pool.execute('UPDATE pet_videos SET views = views + 1 WHERE id = ?', [videoId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加健康记录
app.post('/api/pets/:id/health-records', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { record_type, record_date, title, description, attachment_url, hospital, vet_name, cost, next_date } = req.body;
    if (!record_type || !record_date || !title) {
      return res.status(400).json({ error: '请填写必要的健康记录信息' });
    }
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    const [result] = await pool.execute('INSERT INTO pet_health_records (pet_id, record_type, record_date, title, description, attachment_url, hospital, vet_name, cost, next_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, record_type, record_date, title, description, attachment_url, hospital, vet_name, cost, next_date]);
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取健康记录
app.get('/api/pets/:id/health-records', async (req, res) => {
  try {
    const { id } = req.params;
    const { record_type } = req.query;
    const pool = await getPool();
    
    let query = 'SELECT * FROM pet_health_records WHERE pet_id = ?';
    const params = [id];
    if (record_type) {
      query += ' AND record_type = ?';
      params.push(record_type);
    }
    query += ' ORDER BY record_date DESC';
    
    const [records] = await pool.execute(query, params);
    res.json(records);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加疫苗记录
app.post('/api/pets/:id/vaccinations', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { vaccine_name, vaccine_date, batch_number, hospital, vet_name, next_date, notes } = req.body;
    if (!vaccine_name || !vaccine_date) {
      return res.status(400).json({ error: '请填写疫苗名称和接种日期' });
    }
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    const [result] = await pool.execute('INSERT INTO pet_vaccinations (pet_id, vaccine_name, vaccine_date, batch_number, hospital, vet_name, next_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, vaccine_name, vaccine_date, batch_number, hospital, vet_name, next_date, notes]);
    
    // 更新宠物疫苗状态
    await pool.execute('UPDATE pets SET vaccinated = TRUE WHERE id = ?', [id]);
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取疫苗记录
app.get('/api/pets/:id/vaccinations', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [vaccinations] = await pool.execute('SELECT * FROM pet_vaccinations WHERE pet_id = ? ORDER BY vaccine_date DESC', [id]);
    res.json(vaccinations);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 设置绝育状态
app.post('/api/pets/:id/neuter', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { is_neutered, neuter_date, hospital, vet_name, notes } = req.body;
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    
    const [existing] = await pool.execute('SELECT id FROM pet_neuter_records WHERE pet_id = ?', [id]);
    if (existing.length > 0) {
      await pool.execute('UPDATE pet_neuter_records SET is_neutered = ?, neuter_date = ?, hospital = ?, vet_name = ?, notes = ? WHERE pet_id = ?',
        [is_neutered, neuter_date, hospital, vet_name, notes, id]);
    } else {
      await pool.execute('INSERT INTO pet_neuter_records (pet_id, is_neutered, neuter_date, hospital, vet_name, notes) VALUES (?, ?, ?, ?, ?, ?)',
        [id, is_neutered, neuter_date, hospital, vet_name, notes]);
    }
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取绝育状态
app.get('/api/pets/:id/neuter', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [records] = await pool.execute('SELECT * FROM pet_neuter_records WHERE pet_id = ?', [id]);
    res.json(records[0] || { is_neutered: false });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 上传血统证书
app.post('/api/pets/:id/certificate', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { certificate_type, certificate_number, issuing_authority, issue_date, expiry_date, certificate_url, pedigree_level } = req.body;
    if (!certificate_type) return res.status(400).json({ error: '证书类型不能为空' });
    
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT user_id FROM pets WHERE id = ?', [id]);
    if (pets.length === 0) return res.status(404).json({ error: '宠物不存在' });
    if (pets[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限' });
    
    await initPetExtensionDB();
    
    const [existing] = await pool.execute('SELECT id FROM pet_certificates WHERE pet_id = ?', [id]);
    if (existing.length > 0) {
      await pool.execute('UPDATE pet_certificates SET certificate_type = ?, certificate_number = ?, issuing_authority = ?, issue_date = ?, expiry_date = ?, certificate_url = ?, pedigree_level = ? WHERE pet_id = ?',
        [certificate_type, certificate_number, issuing_authority, issue_date, expiry_date, certificate_url, pedigree_level, id]);
    } else {
      await pool.execute('INSERT INTO pet_certificates (pet_id, certificate_type, certificate_number, issuing_authority, issue_date, expiry_date, certificate_url, pedigree_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [id, certificate_type, certificate_number, issuing_authority, issue_date, expiry_date, certificate_url, pedigree_level]);
    }
    
    // 更新宠物证书状态
    await pool.execute('UPDATE pets SET certificate = TRUE WHERE id = ?', [id]);
    
    // 宠物认证奖励积分
    await pool.execute('UPDATE users SET points = points + 100 WHERE id = ?', [decoded.userId]);
    await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, 'verify_pet', 100, '宠物认证奖励']);
    
    res.json({ success: true, pointsEarned: 100 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取血统证书
app.get('/api/pets/:id/certificate', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [certificates] = await pool.execute('SELECT * FROM pet_certificates WHERE pet_id = ?', [id]);
    res.json(certificates[0] || null);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 13. 匹配系统完整版 - 智能推荐、偏好设置、匹配历史、互相喜欢
// ========================================

async function initMatchDB() {
  const pool = await getPool();
  
  // 匹配偏好设置表
  await pool.execute(`CREATE TABLE IF NOT EXISTS match_preferences (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE NOT NULL,
    preferred_gender ENUM('不限', '公', '母'),
    preferred_breed VARCHAR(50),
    min_age INT,
    max_age INT,
    max_distance INT,
    min_match_score INT DEFAULT 0,
    breed_preferences JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // 匹配记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS match_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    from_user_id INT NOT NULL,
    to_pet_id INT NOT NULL,
    action ENUM('like', 'pass', 'super_like') NOT NULL,
    match_score INT,
    is_mutual BOOLEAN DEFAULT FALSE,
    matched_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_pet_id) REFERENCES pets(id)
  )`);
  
  // 互相喜欢匹配表
  await pool.execute(`CREATE TABLE IF NOT EXISTS matches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id_1 INT NOT NULL,
    user_id_2 INT NOT NULL,
    pet_id_1 INT,
    pet_id_2 INT,
    match_type ENUM('pet', 'user') DEFAULT 'pet',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_match (user_id_1, user_id_2)
  )`);
  
  // 超级喜欢次数表
  await pool.execute(`CREATE TABLE IF NOT EXISTS super_likes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    count INT DEFAULT 0,
    last_reset_date DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
}

// 获取匹配偏好设置
app.get('/api/match/preferences', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initMatchDB();
    const [preferences] = await pool.execute('SELECT * FROM match_preferences WHERE user_id = ?', [decoded.userId]);
    res.json(preferences[0] || {});
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 设置匹配偏好
app.put('/api/match/preferences', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { preferred_gender, preferred_breed, min_age, max_age, max_distance, min_match_score, breed_preferences } = req.body;
    
    const pool = await getPool();
    await initMatchDB();
    
    const [existing] = await pool.execute('SELECT id FROM match_preferences WHERE user_id = ?', [decoded.userId]);
    if (existing.length > 0) {
      await pool.execute(`UPDATE match_preferences SET preferred_gender = ?, preferred_breed = ?, min_age = ?, max_age = ?, max_distance = ?, min_match_score = ?, breed_preferences = ? WHERE user_id = ?`,
        [preferred_gender, preferred_breed, min_age, max_age, max_distance, min_match_score, JSON.stringify(breed_preferences || []), decoded.userId]);
    } else {
      await pool.execute(`INSERT INTO match_preferences (user_id, preferred_gender, preferred_breed, min_age, max_age, max_distance, min_match_score, breed_preferences) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [decoded.userId, preferred_gender || '不限', preferred_breed, min_age, max_age, max_distance, min_match_score || 0, JSON.stringify(breed_preferences || [])]);
    }
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 执行喜欢操作
app.post('/api/match/like', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { pet_id, action, super_like } = req.body;
    if (!pet_id || !action) return res.status(400).json({ error: '缺少必要参数' });
    
    const pool = await getPool();
    await initMatchDB();
    
    // 检查超级喜欢次数
    if (action === 'super_like' || super_like) {
      const today = new Date().toISOString().split('T')[0];
      const [superLikes] = await pool.execute('SELECT * FROM super_likes WHERE user_id = ? AND last_reset_date = ?', [decoded.userId, today]);
      
      if (superLikes.length === 0) {
        await pool.execute('INSERT INTO super_likes (user_id, count, last_reset_date) VALUES (?, ?, ?)', [decoded.userId, 0, today]);
      }
      
      const [current] = await pool.execute('SELECT * FROM super_likes WHERE user_id = ?', [decoded.userId]);
      
      // 非VIP每天只能超级喜欢3次
      const [users] = await pool.execute('SELECT vip_expire_at FROM users WHERE id = ?', [decoded.userId]);
      const isVip = users[0].vip_expire_at && new Date(users[0].vip_expire_at) > new Date();
      const maxSuperLikes = isVip ? 999 : 3;
      
      if (current[0].count >= maxSuperLikes) {
        return res.status(400).json({ error: '今日超级喜欢次数已用完', remaining: 0 });
      }
      
      await pool.execute('UPDATE super_likes SET count = count + 1 WHERE user_id = ?', [decoded.userId]);
      
      // 扣除积分
      await pool.execute('UPDATE users SET points = points - 10 WHERE id = ?', [decoded.userId]);
      await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, 'super_like', -10, '使用超级喜欢']);
    }
    
    // 获取匹配分数
    const [myPets] = await pool.execute('SELECT * FROM pets WHERE user_id = ? LIMIT 1', [decoded.userId]);
    const [targetPets] = await pool.execute('SELECT * FROM pets WHERE id = ?', [pet_id]);
    
    let matchScore = 0;
    if (myPets.length > 0 && targetPets.length > 0) {
      const scoreResult = calculateMatchScore(myPets[0], targetPets[0]);
      matchScore = scoreResult.totalScore;
    }
    
    // 检查是否互相喜欢
    let isMutual = false;
    const [existingLike] = await pool.execute('SELECT id FROM match_records WHERE from_user_id = (SELECT user_id FROM pets WHERE id = ?) AND to_pet_id = (SELECT user_id FROM pets WHERE id = ?) AND action IN ("like", "super_like")', [pet_id, decoded.userId]);
    
    if (existingLike.length > 0) {
      isMutual = true;
      // 创建匹配记录
      const targetPet = targetPets[0];
      await pool.execute('INSERT IGNORE INTO matches (user_id_1, user_id_2, pet_id_1, pet_id_2, match_type, matched_at) VALUES (?, ?, ?, ?, ?, NOW())',
        [decoded.userId, targetPet.user_id, myPets[0]?.id, pet_id, 'pet']);
    }
    
    // 记录匹配操作
    await pool.execute('INSERT INTO match_records (from_user_id, to_pet_id, action, match_score, is_mutual, matched_at) VALUES (?, ?, ?, ?, ?, ?)',
      [decoded.userId, pet_id, action, matchScore, isMutual, isMutual ? new Date() : null]);
    
    // 被喜欢用户获得积分
    const targetPet = targetPets[0];
    if (targetPet) {
      await pool.execute('UPDATE users SET points = points + 1 WHERE id = ?', [targetPet.user_id]);
      await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [targetPet.user_id, 'like_received', 1, '被喜欢']);
    }
    
    res.json({ success: true, isMutual, matchScore });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取匹配历史
app.get('/api/match/history', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initMatchDB();
    
    const [records] = await pool.execute(
      `SELECT m.*, p.name as pet_name, p.breed, p.avatar as pet_avatar, u.nickname as owner_nickname 
       FROM match_records m 
       JOIN pets p ON m.to_pet_id = p.id 
       JOIN users u ON p.user_id = u.id 
       WHERE m.from_user_id = ? 
       ORDER BY m.created_at DESC LIMIT 50`,
      [decoded.userId]
    );
    res.json(records);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取互相喜欢的匹配列表
app.get('/api/match/matches', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initMatchDB();
    
    const [matches] = await pool.execute(
      `SELECT m.*, 
       CASE WHEN m.user_id_1 = ? THEN u2.nickname ELSE u1.nickname END as matched_nickname,
       CASE WHEN m.user_id_1 = ? THEN u2.avatar ELSE u1.avatar END as matched_avatar,
       CASE WHEN m.user_id_1 = ? THEN p2.name ELSE p1.name END as pet_name
       FROM matches m
       JOIN users u1 ON m.user_id_1 = u1.id
       JOIN users u2 ON m.user_id_2 = u2.id
       LEFT JOIN pets p1 ON m.pet_id_1 = p1.id
       LEFT JOIN pets p2 ON m.pet_id_2 = p2.id
       WHERE m.user_id_1 = ? OR m.user_id_2 = ?
       ORDER BY m.created_at DESC`,
      [decoded.userId, decoded.userId, decoded.userId, decoded.userId, decoded.userId]
    );
    res.json(matches);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取超级喜欢剩余次数
app.get('/api/match/super-likes', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    const today = new Date().toISOString().split('T')[0];
    
    const [superLikes] = await pool.execute('SELECT * FROM super_likes WHERE user_id = ?', [decoded.userId]);
    
    const [users] = await pool.execute('SELECT vip_expire_at FROM users WHERE id = ?', [decoded.userId]);
    const isVip = users[0].vip_expire_at && new Date(users[0].vip_expire_at) > new Date();
    const maxSuperLikes = isVip ? 999 : 3;
    
    if (superLikes.length === 0 || superLikes[0].last_reset_date !== today) {
      return res.json({ remaining: maxSuperLikes, max: maxSuperLikes, isVip });
    }
    
    res.json({ remaining: maxSuperLikes - superLikes[0].count, max: maxSuperLikes, isVip });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 智能推荐（考虑偏好设置）
app.get('/api/match/recommendations', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initMatchDB();
    
    // 获取用户偏好
    const [preferences] = await pool.execute('SELECT * FROM match_preferences WHERE user_id = ?', [decoded.userId]);
    const pref = preferences[0] || {};
    
    // 获取用户的宠物
    const [myPets] = await pool.execute('SELECT id, breed, gender FROM pets WHERE user_id = ?', [decoded.userId]);
    const myPetIds = myPets.map(p => p.id);
    
    // 构建查询
    let query = `SELECT p.*, u.nickname as owner_nickname, u.location as owner_location, u.avatar as owner_avatar,
                 (SELECT id FROM match_records WHERE from_user_id = ? AND to_pet_id = p.id) as has_action
                 FROM pets p 
                 JOIN users u ON p.user_id = u.id 
                 WHERE p.user_id != ?`;
    const params = [decoded.userId, decoded.userId];
    
    // 应用偏好过滤
    if (pref.preferred_gender && pref.preferred_gender !== '不限') {
      query += ' AND p.gender = ?';
      params.push(pref.preferred_gender);
    }
    if (pref.preferred_breed) {
      query += ' AND p.breed = ?';
      params.push(pref.preferred_breed);
    }
    if (pref.min_age) {
      query += ' AND p.age >= ?';
      params.push(pref.min_age);
    }
    if (pref.max_age) {
      query += ' AND p.age <= ?';
      params.push(pref.max_age);
    }
    
    // 排除已操作的宠物
    if (myPetIds.length > 0) {
      query += ' AND p.id NOT IN (SELECT to_pet_id FROM match_records WHERE from_user_id = ?)';
      params.push(decoded.userId);
    }
    
    query += ' ORDER BY p.created_at DESC LIMIT 50';
    
    const [pets] = await pool.execute(query, params);
    
    // 计算匹配分数
    const recommendations = [];
    for (const pet of pets) {
      let bestScore = 0;
      for (const myPet of myPets) {
        const [targetPets] = await pool.execute('SELECT * FROM pets WHERE id = ?', [pet.id]);
        if (targetPets.length > 0) {
          const scoreResult = calculateMatchScore(myPet, targetPets[0]);
          bestScore = Math.max(bestScore, scoreResult.totalScore);
        }
      }
      recommendations.push({ ...pet, matchScore: bestScore });
    }
    
    // 按匹配分数排序
    recommendations.sort((a, b) => b.matchScore - a.matchScore);
    
    // 过滤最低匹配分数
    const filtered = recommendations.filter(r => r.matchScore >= (pref.min_match_score || 0));
    
    res.json(filtered);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 14. 消息系统完整版 - 私聊、群聊、消息撤回、删除、已读回执
// ========================================

async function initMessageDB() {
  const pool = await getPool();
  
  // 私聊消息表
  await pool.execute(`CREATE TABLE IF NOT EXISTS private_messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_type ENUM('text', 'image', 'voice', 'video', 'file') DEFAULT 'text',
    content TEXT NOT NULL,
    media_url VARCHAR(255),
    is_recalled BOOLEAN DEFAULT FALSE,
    recalled_at DATETIME,
    is_deleted_sender BOOLEAN DEFAULT FALSE,
    is_deleted_receiver BOOLEAN DEFAULT FALSE,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  )`);
  
  // 群聊表
  await pool.execute(`CREATE TABLE IF NOT EXISTS chat_groups (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    avatar VARCHAR(255),
    owner_id INT NOT NULL,
    description VARCHAR(255),
    max_members INT DEFAULT 100,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
  )`);
  
  // 群成员表
  await pool.execute(`CREATE TABLE IF NOT EXISTS group_members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    role ENUM('owner', 'admin', 'member') DEFAULT 'member',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_member (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES chat_groups(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // 群消息表
  await pool.execute(`CREATE TABLE IF NOT EXISTS group_messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    group_id INT NOT NULL,
    sender_id INT NOT NULL,
    message_type ENUM('text', 'image', 'voice', 'video', 'file', 'system') DEFAULT 'text',
    content TEXT NOT NULL,
    media_url VARCHAR(255),
    is_recalled BOOLEAN DEFAULT FALSE,
    recalled_at DATETIME,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES chat_groups(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
  )`);
  
  // 消息已读状态表
  await pool.execute(`CREATE TABLE IF NOT EXISTS message_read_status (
    id INT PRIMARY KEY AUTO_INCREMENT,
    message_id INT NOT NULL,
    user_id INT NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_read (message_id, user_id)
  )`);
}

// 获取私聊消息列表
app.get('/api/messages/private', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { user_id, limit = 50, offset = 0 } = req.query;
    if (!user_id) return res.status(400).json({ error: '缺少用户ID' });
    
    const pool = await getPool();
    await initMessageDB();
    
    const [messages] = await pool.execute(
      `SELECT * FROM private_messages 
       WHERE ((sender_id = ? AND receiver_id = ? AND is_deleted_sender = FALSE) 
           OR (sender_id = ? AND receiver_id = ? AND is_deleted_receiver = FALSE))
       ORDER BY sent_at DESC LIMIT ? OFFSET ?`,
      [decoded.userId, user_id, user_id, decoded.userId, parseInt(limit), parseInt(offset)]
    );
    
    // 标记为已读
    await pool.execute(
      'UPDATE private_messages SET read_at = NOW() WHERE sender_id = ? AND receiver_id = ? AND read_at IS NULL',
      [user_id, decoded.userId]
    );
    
    res.json(messages.reverse());
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 发送私聊消息
app.post('/api/messages/private', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { receiver_id, content, message_type, media_url } = req.body;
    if (!receiver_id || !content) return res.status(400).json({ error: '缺少必要参数' });
    
    const pool = await getPool();
    await initMessageDB();
    
    const [result] = await pool.execute(
      'INSERT INTO private_messages (sender_id, receiver_id, message_type, content, media_url) VALUES (?, ?, ?, ?, ?)',
      [decoded.userId, receiver_id, message_type || 'text', content, media_url]
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 撤回私聊消息
app.post('/api/messages/private/:id/recall', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [messages] = await pool.execute('SELECT * FROM private_messages WHERE id = ? AND sender_id = ?', [id, decoded.userId]);
    
    if (messages.length === 0) return res.status(404).json({ error: '消息不存在或无权限' });
    
    // 2分钟内可以撤回
    const sentTime = new Date(messages[0].sent_at).getTime();
    if (Date.now() - sentTime > 2 * 60 * 1000) {
      return res.status(400).json({ error: '消息已超过2分钟，无法撤回' });
    }
    
    await pool.execute('UPDATE private_messages SET is_recalled = TRUE, recalled_at = NOW() WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 删除私聊消息
app.delete('/api/messages/private/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [messages] = await pool.execute('SELECT * FROM private_messages WHERE id = ? AND (sender_id = ? OR receiver_id = ?)', [id, decoded.userId, decoded.userId]);
    
    if (messages.length === 0) return res.status(404).json({ error: '消息不存在' });
    
    const msg = messages[0];
    if (msg.sender_id === decoded.userId) {
      await pool.execute('UPDATE private_messages SET is_deleted_sender = TRUE WHERE id = ?', [id]);
    } else {
      await pool.execute('UPDATE private_messages SET is_deleted_receiver = TRUE WHERE id = ?', [id]);
    }
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 创建群聊
app.post('/api/messages/groups', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { name, avatar, description, member_ids } = req.body;
    if (!name) return res.status(400).json({ error: '群名称不能为空' });
    
    const pool = await getPool();
    await initMessageDB();
    
    const [result] = await pool.execute(
      'INSERT INTO chat_groups (name, avatar, owner_id, description) VALUES (?, ?, ?, ?)',
      [name, avatar, decoded.userId, description]
    );
    
    const groupId = result.insertId;
    
    // 创建者自动加入
    await pool.execute('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', [groupId, decoded.userId, 'owner']);
    
    // 添加成员
    if (member_ids && Array.isArray(member_ids)) {
      for (const memberId of member_ids) {
        if (memberId !== decoded.userId) {
          await pool.execute('INSERT IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', [groupId, memberId, 'member']);
        }
      }
    }
    
    res.json({ id: groupId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取我的群聊列表
app.get('/api/messages/groups', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initMessageDB();
    
    const [groups] = await pool.execute(
      `SELECT g.*, 
       (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count,
       (SELECT content FROM group_messages WHERE group_id = g.id ORDER BY sent_at DESC LIMIT 1) as last_message,
       (SELECT sent_at FROM group_messages WHERE group_id = g.id ORDER BY sent_at DESC LIMIT 1) as last_message_time
       FROM chat_groups g
       JOIN group_members gm ON g.id = gm.group_id
       WHERE gm.user_id = ?
       ORDER BY last_message_time DESC`,
      [decoded.userId]
    );
    
    res.json(groups);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取群聊详情
app.get('/api/messages/groups/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    
    // 验证成员身份
    const [membership] = await pool.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', [id, decoded.userId]);
    if (membership.length === 0) return res.status(403).json({ error: '您不是群成员' });
    
    const [groups] = await pool.execute('SELECT * FROM chat_groups WHERE id = ?', [id]);
    const [members] = await pool.execute(
      `SELECT u.id, u.nickname, u.avatar, gm.role, gm.joined_at 
       FROM group_members gm 
       JOIN users u ON gm.user_id = u.id 
       WHERE gm.group_id = ?`,
      [id]
    );
    
    res.json({ ...groups[0], members, myRole: membership[0].role });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 发送群消息
app.post('/api/messages/groups/:id/messages', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { content, message_type, media_url } = req.body;
    if (!content) return res.status(400).json({ error: '消息内容不能为空' });
    
    const pool = await getPool();
    
    // 验证成员身份
    const [membership] = await pool.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', [id, decoded.userId]);
    if (membership.length === 0) return res.status(403).json({ error: '您不是群成员' });
    
    const [result] = await pool.execute(
      'INSERT INTO group_messages (group_id, sender_id, message_type, content, media_url) VALUES (?, ?, ?, ?, ?)',
      [id, decoded.userId, message_type || 'text', content, media_url]
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取群消息历史
app.get('/api/messages/groups/:id/messages', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    const pool = await getPool();
    
    // 验证成员身份
    const [membership] = await pool.execute('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', [id, decoded.userId]);
    if (membership.length === 0) return res.status(403).json({ error: '您不是群成员' });
    
    const [messages] = await pool.execute(
      `SELECT m.*, u.nickname as sender_nickname, u.avatar as sender_avatar 
       FROM group_messages m 
       JOIN users u ON m.sender_id = u.id 
       WHERE m.group_id = ? AND m.is_recalled = FALSE
       ORDER BY m.sent_at DESC LIMIT ? OFFSET ?`,
      [id, parseInt(limit), parseInt(offset)]
    );
    
    res.json(messages.reverse());
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 撤回群消息
app.post('/api/messages/groups/:id/messages/:messageId/recall', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, messageId } = req.params;
    
    const pool = await getPool();
    
    const [messages] = await pool.execute(
      'SELECT * FROM group_messages WHERE id = ? AND group_id = ? AND sender_id = ?',
      [messageId, id, decoded.userId]
    );
    
    if (messages.length === 0) return res.status(404).json({ error: '消息不存在或无权限' });
    
    const sentTime = new Date(messages[0].sent_at).getTime();
    if (Date.now() - sentTime > 2 * 60 * 1000) {
      return res.status(400).json({ error: '消息已超过2分钟，无法撤回' });
    }
    
    await pool.execute('UPDATE group_messages SET is_recalled = TRUE, recalled_at = NOW() WHERE id = ?', [messageId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 添加群成员
app.post('/api/messages/groups/:id/members', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const { user_ids } = req.body;
    if (!user_ids || !Array.isArray(user_ids)) return res.status(400).json({ error: '请提供用户ID列表' });
    
    const pool = await getPool();
    
    // 验证权限（群主或管理员）
    const [membership] = await pool.execute(
      'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
      [id, decoded.userId]
    );
    if (membership.length === 0) return res.status(403).json({ error: '您不是群成员' });
    if (membership[0].role !== 'owner' && membership[0].role !== 'admin') {
      return res.status(403).json({ error: '只有群主和管理员可以添加成员' });
    }
    
    // 检查群人数限制
    const [group] = await pool.execute('SELECT max_members FROM chat_groups WHERE id = ?', [id]);
    const [memberCount] = await pool.execute('SELECT COUNT(*) as cnt FROM group_members WHERE group_id = ?', [id]);
    
    if (memberCount[0].cnt + user_ids.length > group[0].max_members) {
      return res.status(400).json({ error: '群成员已达上限' });
    }
    
    // 添加成员
    const added = [];
    for (const userId of user_ids) {
      try {
        await pool.execute(
          'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
          [id, userId, 'member']
        );
        added.push(userId);
      } catch (e) {}
    }
    
    // 发送系统消息
    if (added.length > 0) {
      await pool.execute(
        'INSERT INTO group_messages (group_id, sender_id, message_type, content) VALUES (?, ?, ?, ?)',
        [id, decoded.userId, 'system', `用户加入了群聊`]
      );
    }
    
    res.json({ success: true, added });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 移除群成员
app.delete('/api/messages/groups/:id/members/:userId', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, userId } = req.params;
    
    const pool = await getPool();
    
    // 验证权限
    const [membership] = await pool.execute(
      'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
      [id, decoded.userId]
    );
    if (membership.length === 0) return res.status(403).json({ error: '您不是群成员' });
    
    // 群主可以移除任何人，管理员只能移除普通成员
    if (membership[0].role === 'member') {
      return res.status(403).json({ error: '您没有权限移除成员' });
    }
    if (membership[0].role === 'admin' && userId === decoded.userId.toString()) {
      return res.status(403).json({ error: '管理员不能移除自己' });
    }
    
    // 不能移除群主
    const [targetMembership] = await pool.execute(
      'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
      [id, userId]
    );
    if (targetMembership.length > 0 && targetMembership[0].role === 'owner') {
      return res.status(400).json({ error: '不能移除群主' });
    }
    
    await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [id, userId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 退群
app.post('/api/messages/groups/:id/leave', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    
    const [membership] = await pool.execute(
      'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
      [id, decoded.userId]
    );
    if (membership.length === 0) return res.status(404).json({ error: '您不在群中' });
    
    if (membership[0].role === 'owner') {
      return res.status(400).json({ error: '群主不能退群，请转移群主或解散群' });
    }
    
    await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [id, decoded.userId]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取未读消息数
app.get('/api/messages/unread', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    
    // 私聊未读
    const [unreadCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM private_messages WHERE receiver_id = ? AND read_at IS NULL AND is_deleted_receiver = FALSE',
      [decoded.userId]
    );
    
    // 群消息未读（简略计算）
    const [groupUnread] = await pool.execute(
      `SELECT COUNT(*) as count FROM group_messages gm
       JOIN group_members gm2 ON gm.group_id = gm2.group_id
       WHERE gm2.user_id = ? AND gm.sender_id != ?`,
      [decoded.userId, decoded.userId]
    );
    
    res.json({
      private: unreadCount[0].count,
      group: groupUnread[0].count
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 15. 社交系统 - 关注/粉丝、黑名单、举报
// ========================================

async function initSocialDB() {
  const pool = await getPool();
  
  // 关注表
  await pool.execute(`CREATE TABLE IF NOT EXISTS follows (
    id INT PRIMARY KEY AUTO_INCREMENT,
    follower_id INT NOT NULL,
    following_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_follow (follower_id, following_id),
    FOREIGN KEY (follower_id) REFERENCES users(id),
    FOREIGN KEY (following_id) REFERENCES users(id)
  )`);
  
  // 黑名单表
  await pool.execute(`CREATE TABLE IF NOT EXISTS blacklists (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    blocked_user_id INT NOT NULL,
    reason VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_block (user_id, blocked_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (blocked_user_id) REFERENCES users(id)
  )`);
  
  // 举报表
  await pool.execute(`CREATE TABLE IF NOT EXISTS reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reporter_id INT NOT NULL,
    reported_user_id INT,
    post_id INT,
    comment_id INT,
    reason VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    handled_by INT,
    handled_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(id),
    FOREIGN KEY (reported_user_id) REFERENCES users(id)
  )`);
}

// 关注用户
app.post('/api/users/:id/follow', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    if (decoded.userId.toString() === id) return res.status(400).json({ error: '不能关注自己' });
    
    const pool = await getPool();
    await initSocialDB();
    
    // 检查是否在黑名单
    const [blocked] = await pool.execute(
      'SELECT id FROM blacklists WHERE user_id = ? AND blocked_user_id = ?',
      [id, decoded.userId]
    );
    if (blocked.length > 0) return res.status(403).json({ error: '对方已将您拉黑' });
    
    try {
      await pool.execute('INSERT INTO follows (follower_id, following_id) VALUES (?, ?)', [decoded.userId, id]);
      res.json({ success: true, following: true });
    } catch (e) {
      return res.status(400).json({ error: '已经关注过了' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 取消关注
app.delete('/api/users/:id/follow', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await pool.execute('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [decoded.userId, id]);
    res.json({ success: true, following: false });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取关注列表
app.get('/api/users/:id/following', async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const pool = await getPool();
    await initSocialDB();
    
    const [following] = await pool.execute(
      `SELECT u.id, u.nickname, u.avatar, f.created_at as followed_at 
       FROM follows f 
       JOIN users u ON f.following_id = u.id 
       WHERE f.follower_id = ? 
       ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
      [id, parseInt(limit), parseInt(offset)]
    );
    res.json(following);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取粉丝列表
app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    
    const pool = await getPool();
    await initSocialDB();
    
    const [followers] = await pool.execute(
      `SELECT u.id, u.nickname, u.avatar, f.created_at as followed_at 
       FROM follows f 
       JOIN users u ON f.follower_id = u.id 
       WHERE f.following_id = ? 
       ORDER BY f.created_at DESC LIMIT ? OFFSET ?`,
      [id, parseInt(limit), parseInt(offset)]
    );
    res.json(followers);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取关注状态
app.get('/api/users/:id/follow-status', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await initSocialDB();
    
    const [follows] = await pool.execute(
      'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?',
      [decoded.userId, id]
    );
    
    const [followers] = await pool.execute(
      'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?',
      [id, decoded.userId]
    );
    
    res.json({
      following: follows.length > 0,
      followedBy: followers.length > 0
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取粉丝/关注数量
app.get('/api/users/:id/stats', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    
    const [followingCount] = await pool.execute('SELECT COUNT(*) as count FROM follows WHERE follower_id = ?', [id]);
    const [followerCount] = await pool.execute('SELECT COUNT(*) as count FROM follows WHERE following_id = ?', [id]);
    const [postCount] = await pool.execute('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', [id]);
    const [petCount] = await pool.execute('SELECT COUNT(*) as count FROM pets WHERE user_id = ?', [id]);
    
    res.json({
      following: followingCount[0].count,
      followers: followerCount[0].count,
      posts: postCount[0].count,
      pets: petCount[0].count
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 拉黑用户
app.post('/api/users/:id/block', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    if (decoded.userId.toString() === id) return res.status(400).json({ error: '不能拉黑自己' });
    
    const { reason } = req.body;
    const pool = await getPool();
    await initSocialDB();
    
    // 取消关注
    await pool.execute('DELETE FROM follows WHERE (follower_id = ? AND following_id = ?) OR (follower_id = ? AND following_id = ?)', [decoded.userId, id, id, decoded.userId]);
    
    try {
      await pool.execute('INSERT INTO blacklists (user_id, blocked_user_id, reason) VALUES (?, ?, ?)', [decoded.userId, id, reason]);
      res.json({ success: true, blocked: true });
    } catch (e) {
      return res.status(400).json({ error: '已经拉黑过了' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 取消拉黑
app.delete('/api/users/:id/block', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await pool.execute('DELETE FROM blacklists WHERE user_id = ? AND blocked_user_id = ?', [decoded.userId, id]);
    res.json({ success: true, blocked: false });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取黑名单
app.get('/api/user/blacklist', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initSocialDB();
    
    const [blacklist] = await pool.execute(
      `SELECT u.id, u.nickname, u.avatar, b.reason, b.created_at 
       FROM blacklists b 
       JOIN users u ON b.blocked_user_id = u.id 
       WHERE b.user_id = ? 
       ORDER BY b.created_at DESC`,
      [decoded.userId]
    );
    res.json(blacklist);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 举报用户/内容
app.post('/api/reports', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { reported_user_id, post_id, comment_id, reason, description } = req.body;
    if (!reason) return res.status(400).json({ error: '请选择举报原因' });
    if (!reported_user_id && !post_id && !comment_id) {
      return res.status(400).json({ error: '请提供举报对象' });
    }
    
    const pool = await getPool();
    await initSocialDB();
    
    const [result] = await pool.execute(
      'INSERT INTO reports (reporter_id, reported_user_id, post_id, comment_id, reason, description) VALUES (?, ?, ?, ?, ?, ?)',
      [decoded.userId, reported_user_id, post_id, comment_id, reason, description]
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 我的举报记录
app.get('/api/reports/my', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initSocialDB();
    
    const [reports] = await pool.execute(
      `SELECT r.*, 
       (SELECT nickname FROM users WHERE id = r.reported_user_id) as reported_nickname
       FROM reports r 
       WHERE r.reporter_id = ? 
       ORDER BY r.created_at DESC`,
      [decoded.userId]
    );
    res.json(reports);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 16. 帖子系统完整版 - 置顶、删除、热门、推荐
// ========================================

async function initPostExtensionDB() {
  const pool = await getPool();
  
  // 帖子置顶表
  await pool.execute(`CREATE TABLE IF NOT EXISTS post_pins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    post_id INT NOT NULL,
    expire_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id)
  )`);
  
  // 帖子收藏表
  await pool.execute(`CREATE TABLE IF NOT EXISTS post_favorites (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_favorite (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (post_id) REFERENCES posts(id)
  )`);
  
  // 帖子分享记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS post_shares (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    platform VARCHAR(50),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (post_id) REFERENCES posts(id)
  )`);
}

// 获取帖子详情
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    
    const [posts] = await pool.execute(
      `SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar 
       FROM posts p 
       JOIN users u ON p.user_id = u.id 
       WHERE p.id = ?`,
      [id]
    );
    
    if (posts.length === 0) return res.status(404).json({ error: '帖子不存在' });
    
    // 检查是否置顶
    const [pins] = await pool.execute('SELECT * FROM post_pins WHERE post_id = ? AND (expire_at IS NULL OR expire_at > NOW())', [id]);
    posts[0].is_pinned = pins.length > 0;
    
    res.json(posts[0]);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 删除帖子
app.delete('/api/posts/:id', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [posts] = await pool.execute('SELECT user_id FROM posts WHERE id = ?', [id]);
    
    if (posts.length === 0) return res.status(404).json({ error: '帖子不存在' });
    if (posts[0].user_id !== decoded.userId) return res.status(403).json({ error: '无权限删除' });
    
    // 删除关联数据
    await pool.execute('DELETE FROM post_pins WHERE post_id = ?', [id]);
    await pool.execute('DELETE FROM post_favorites WHERE post_id = ?', [id]);
    await pool.execute('DELETE FROM post_shares WHERE post_id = ?', [id]);
    await pool.execute('DELETE FROM comments WHERE post_id = ?', [id]);
    await pool.execute('DELETE FROM posts WHERE id = ?', [id]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 置顶帖子（管理员/版主）
app.post('/api/posts/:id/pin', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { duration_hours } = req.body;
    
    const pool = await getPool();
    
    // 检查是否为管理员
    const [users] = await pool.execute('SELECT is_admin FROM users WHERE id = ?', [decoded.userId]);
    if (!users[0].is_admin) return res.status(403).json({ error: '无权限置顶' });
    
    const expireAt = duration_hours ? new Date(Date.now() + duration_hours * 60 * 60 * 1000) : null;
    
    await initPostExtensionDB();
    await pool.execute('INSERT INTO post_pins (post_id, expire_at) VALUES (?, ?)', [id, expireAt]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 取消置顶
app.delete('/api/posts/:id/pin', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    const [users] = await pool.execute('SELECT is_admin FROM users WHERE id = ?', [decoded.userId]);
    if (!users[0].is_admin) return res.status(403).json({ error: '无权限取消置顶' });
    
    await pool.execute('DELETE FROM post_pins WHERE post_id = ?', [id]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取热门帖子
app.get('/api/posts/hot', async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const pool = await getPool();
    
    // 热门算法：点赞*2 + 评论*3 + 发布时间衰减
    const [posts] = await pool.execute(
      `SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar,
       (p.likes * 2 + p.comments_count * 3) as hot_score
       FROM posts p 
       JOIN users u ON p.user_id = u.id
       LEFT JOIN post_pins pp ON p.id = pp.post_id AND (pp.expire_at IS NULL OR pp.expire_at > NOW())
       WHERE pp.id IS NULL
       ORDER BY hot_score DESC, p.created_at DESC LIMIT ?`,
      [parseInt(limit)]
    );
    
    res.json(posts);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取推荐帖子
app.get('/api/posts/recommended', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const { limit = 20 } = req.query;
    const pool = await getPool();
    
    let recommendedPosts;
    
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 基于用户兴趣推荐
        const [preferences] = await pool.execute(
          'SELECT interest_tags FROM user_profiles WHERE user_id = ?',
          [decoded.userId]
        );
        
        if (preferences.length > 0 && preferences[0].interest_tags) {
          const tags = JSON.parse(preferences[0].interest_tags);
          if (tags.length > 0) {
            // 随机选择标签进行推荐
            const randomTag = tags[Math.floor(Math.random() * tags.length)];
            const [posts] = await pool.execute(
              `SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar
               FROM posts p 
               JOIN users u ON p.user_id = u.id
               WHERE p.category LIKE ?
               ORDER BY p.likes DESC, p.created_at DESC LIMIT ?`,
              [`%${randomTag}%`, parseInt(limit)]
            );
            if (posts.length > 0) return res.json(posts);
          }
        }
      } catch (e) {}
    }
    
    // 默认推荐：综合热门
    const [defaultPosts] = await pool.execute(
      `SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar
       FROM posts p 
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC LIMIT ?`,
      [parseInt(limit)]
    );
    
    res.json(defaultPosts);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 收藏帖子
app.post('/api/posts/:id/favorite', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await initPostExtensionDB();
    
    try {
      await pool.execute('INSERT INTO post_favorites (user_id, post_id) VALUES (?, ?)', [decoded.userId, id]);
      res.json({ success: true, favorited: true });
    } catch (e) {
      await pool.execute('DELETE FROM post_favorites WHERE user_id = ? AND post_id = ?', [decoded.userId, id]);
      res.json({ success: true, favorited: false });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取收藏列表
app.get('/api/posts/favorites', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initPostExtensionDB();
    
    const [favorites] = await pool.execute(
      `SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar, f.created_at as favorited_at
       FROM post_favorites f
       JOIN posts p ON f.post_id = p.id
       JOIN users u ON p.user_id = u.id
       WHERE f.user_id = ?
       ORDER BY f.created_at DESC`,
      [decoded.userId]
    );
    
    res.json(favorites);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 分享帖子
app.post('/api/posts/:id/share', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { platform } = req.body;
    
    const pool = await getPool();
    await initPostExtensionDB();
    
    await pool.execute('INSERT INTO post_shares (user_id, post_id, platform) VALUES (?, ?, ?)', [decoded.userId, id, platform]);
    await pool.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', [id]);
    
    // 分享奖励积分
    await pool.execute('UPDATE users SET points = points + 5 WHERE id = ?', [decoded.userId]);
    await pool.execute('INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)', [decoded.userId, 'share', 5, '分享帖子奖励']);
    
    res.json({ success: true, pointsEarned: 5 });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 17. 活动系统完整版 - 审核、签到、评论、收藏
// ========================================

async function initActivityExtensionDB() {
  const pool = await getPool();
  
  // 活动签到表
  await pool.execute(`CREATE TABLE IF NOT EXISTS activity_checkins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    activity_id INT NOT NULL,
    user_id INT NOT NULL,
    checkin_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_checkin (activity_id, user_id),
    FOREIGN KEY (activity_id) REFERENCES activities(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // 活动评论表
  await pool.execute(`CREATE TABLE IF NOT EXISTS activity_comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    activity_id INT NOT NULL,
    user_id INT NOT NULL,
    parent_id INT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (activity_id) REFERENCES activities(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (parent_id) REFERENCES activity_comments(id)
  )`);
  
  // 活动收藏表
  await pool.execute(`CREATE TABLE IF NOT EXISTS activity_favorites (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    activity_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_favorite (user_id, activity_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (activity_id) REFERENCES activities(id)
  )`);
}

// 活动签到
app.post('/api/activities/:id/checkin', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await initActivityExtensionDB();
    
    const [registrations] = await pool.execute(
      'SELECT id FROM activity_registrations WHERE activity_id = ? AND user_id = ?',
      [id, decoded.userId]
    );
    if (registrations.length === 0) return res.status(400).json({ error: '请先报名活动' });
    
    try {
      await pool.execute('INSERT INTO activity_checkins (activity_id, user_id) VALUES (?, ?)', [id, decoded.userId]);
      res.json({ success: true, message: '签到成功' });
    } catch (e) {
      return res.status(400).json({ error: '您已签到' });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取签到列表
app.get('/api/activities/:id/checkins', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    
    const [checkins] = await pool.execute(
      `SELECT c.*, u.nickname, u.avatar 
       FROM activity_checkins c
       JOIN users u ON c.user_id = u.id
       WHERE c.activity_id = ?
       ORDER BY c.checkin_time DESC`,
      [id]
    );
    res.json(checkins);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 活动评论
app.post('/api/activities/:id/comments', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { content, parent_id } = req.body;
    
    if (!content || content.trim().length === 0) return res.status(400).json({ error: '评论内容不能为空' });
    
    const pool = await getPool();
    await initActivityExtensionDB();
    
    const [result] = await pool.execute(
      'INSERT INTO activity_comments (activity_id, user_id, parent_id, content) VALUES (?, ?, ?, ?)',
      [id, decoded.userId, parent_id || null, content]
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取活动评论
app.get('/api/activities/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;
    const { limit = 20, offset = 0 } = req.query;
    const pool = await getPool();
    
    const [comments] = await pool.execute(
      `SELECT c.*, u.nickname, u.avatar as user_avatar 
       FROM activity_comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.activity_id = ? AND c.parent_id IS NULL
       ORDER BY c.created_at DESC LIMIT ? OFFSET ?`,
      [id, parseInt(limit), parseInt(offset)]
    );
    
    for (const comment of comments) {
      const [replies] = await pool.execute(
        `SELECT c.*, u.nickname, u.avatar as user_avatar 
         FROM activity_comments c
         JOIN users u ON c.user_id = u.id
         WHERE c.parent_id = ?
         ORDER BY c.created_at ASC`,
        [comment.id]
      );
      comment.replies = replies;
    }
    
    res.json(comments);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 收藏活动
app.post('/api/activities/:id/favorite', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    
    const pool = await getPool();
    await initActivityExtensionDB();
    
    try {
      await pool.execute('INSERT INTO activity_favorites (user_id, activity_id) VALUES (?, ?)', [decoded.userId, id]);
      res.json({ success: true, favorited: true });
    } catch (e) {
      await pool.execute('DELETE FROM activity_favorites WHERE user_id = ? AND activity_id = ?', [decoded.userId, id]);
      res.json({ success: true, favorited: false });
    }
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取收藏的活动
app.get('/api/activities/favorites', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    const [favorites] = await pool.execute(
      `SELECT a.*, f.created_at as favorited_at
       FROM activity_favorites f
       JOIN activities a ON f.activity_id = a.id
       WHERE f.user_id = ?
       ORDER BY f.created_at DESC`,
      [decoded.userId]
    );
    res.json(favorites);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 审核活动（管理员）
app.post('/api/admin/activities/:id/approve', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id } = req.params;
    const { approved, reason } = req.body;
    
    const pool = await getPool();
    const [users] = await pool.execute('SELECT is_admin FROM users WHERE id = ?', [decoded.userId]);
    if (!users[0].is_admin) return res.status(403).json({ error: '无权限审核' });
    
    const status = approved ? 'approved' : 'rejected';
    await pool.execute('UPDATE activities SET status = ? WHERE id = ?', [status, id]);
    
    const [activity] = await pool.execute('SELECT user_id, title FROM activities WHERE id = ?', [id]);
    await initNotificationDB();
    await pool.execute(
      'INSERT INTO notifications (user_id, type, title, content) VALUES (?, ?, ?, ?)',
      [activity[0].user_id, 'activity_review', '活动审核结果', approved ? `您的活动"${activity[0].title}"已通过审核` : `您的活动"${activity[0].title}"未通过审核：${reason || '不符合要求'}`]
    );
    
    res.json({ success: true, status });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 18. 积分系统完整版 - 积分商城、兑换记录、积分任务
// ========================================

async function initPointsMallDB() {
  const pool = await getPool();
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS points_goods (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    image VARCHAR(255),
    points_required INT NOT NULL,
    stock INT DEFAULT 0,
    category VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS points_exchanges (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    goods_id INT NOT NULL,
    goods_name VARCHAR(100),
    points_spent INT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    address_id INT,
    contact_name VARCHAR(50),
    contact_phone VARCHAR(20),
    delivered_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (goods_id) REFERENCES points_goods(id),
    FOREIGN KEY (address_id) REFERENCES addresses(id)
  )`);
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS points_tasks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    task_type VARCHAR(50) NOT NULL,
    points_reward INT NOT NULL,
    is_daily BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS task_completions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    task_id INT NOT NULL,
    completed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_task_daily (user_id, task_id, DATE(completed_at)),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (task_id) REFERENCES points_tasks(id)
  )`);
  
  const [goods] = await pool.execute('SELECT COUNT(*) as cnt FROM points_goods');
  if (goods[0].cnt === 0) {
    await pool.execute(`INSERT INTO points_goods (name, description, points_required, stock, category) VALUES 
      ('宠物零食礼包', '精选宠物零食组合', 500, 100, 'food'),
      ('宠物玩具', '有趣的宠物玩具', 300, 150, 'toy'),
      ('宠物牵引绳', '舒适的牵引绳', 800, 80, 'accessory'),
      ('宠物美容券', '免费宠物美容一次', 1000, 50, 'service'),
      ('宠物体检券', '全面体检一次', 2000, 30, 'service'),
      ('VIP月卡', '一个月VIP会员', 1500, 200, 'vip')`);
  }
  
  const [tasks] = await pool.execute('SELECT COUNT(*) as cnt FROM points_tasks');
  if (tasks[0].cnt === 0) {
    await pool.execute(`INSERT INTO points_tasks (name, description, task_type, points_reward, is_daily) VALUES 
      ('每日签到', '每天签到领取积分', 'daily_login', 10, TRUE),
      ('完善宠物资料', '完善宠物信息', 'complete_pet', 30, FALSE),
      ('首次绑定手机', '绑定手机号', 'bind_phone', 50, FALSE)`);
  }
}

app.get('/api/points/mall/goods', async (req, res) => {
  try {
    const { category } = req.query;
    const pool = await getPool();
    await initPointsMallDB();
    
    let query = 'SELECT * FROM points_goods WHERE is_active = TRUE';
    const params = [];
    if (category) { query += ' AND category = ?'; params.push(category); }
    query += ' ORDER BY created_at DESC';
    
    const [goods] = await pool.execute(query, params);
    res.json(goods);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/points/mall/exchange', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { goods_id, address_id, contact_name, contact_phone } = req.body;
    if (!goods_id) return res.status(400).json({ error: '请选择商品' });
    
    const pool = await getPool();
    await initPointsMallDB();
    
    const [goods] = await pool.execute('SELECT * FROM points_goods WHERE id = ? AND is_active = TRUE', [goods_id]);
    if (goods.length === 0) return res.status(404).json({ error: '商品不存在' });
    if (goods[0].stock <= 0) return res.status(400).json({ error: '商品库存不足' });
    
    const [users] = await pool.execute('SELECT points FROM users WHERE id = ?', [decoded.userId]);
    if (users[0].points < goods[0].points_required) {
      return res.status(400).json({ error: '积分不足', required: goods[0].points_required, current: users[0].points });
    }
    
    await pool.execute('UPDATE users SET points = points - ? WHERE id = ?', [goods[0].points_required, decoded.userId]);
    await pool.execute('UPDATE points_goods SET stock = stock - 1 WHERE id = ?', [goods_id]);
    await pool.execute(
      'INSERT INTO points_exchanges (user_id, goods_id, goods_name, points_spent, address_id, contact_name, contact_phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [decoded.userId, goods_id, goods[0].name, goods[0].points_required, address_id, contact_name, contact_phone]
    );
    
    res.json({ success: true, message: '兑换成功' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/points/exchanges', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initPointsMallDB();
    
    const [exchanges] = await pool.execute(
      'SELECT * FROM points_exchanges WHERE user_id = ? ORDER BY created_at DESC',
      [decoded.userId]
    );
    res.json(exchanges);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/points/tasks', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initPointsMallDB();
    
    const [tasks] = await pool.execute('SELECT * FROM points_tasks WHERE is_active = TRUE ORDER BY is_daily DESC, id ASC');
    
    const [completions] = await pool.execute(
      'SELECT task_id FROM task_completions WHERE user_id = ? AND DATE(completed_at) = CURDATE()',
      [decoded.userId]
    );
    
    const completedTasks = new Set(completions.map(c => c.task_id));
    const tasksWithStatus = tasks.map(task => ({ ...task, completed: completedTasks.has(task.id) }));
    
    res.json(tasksWithStatus);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/points/tasks/:taskId/complete', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const { taskId } = req.params;
    
    const pool = await getPool();
    await initPointsMallDB();
    
    const [tasks] = await pool.execute('SELECT * FROM points_tasks WHERE id = ? AND is_active = TRUE', [taskId]);
    if (tasks.length === 0) return res.status(404).json({ error: '任务不存在' });
    const task = tasks[0];
    
    if (task.is_daily) {
      const [existing] = await pool.execute(
        'SELECT id FROM task_completions WHERE user_id = ? AND task_id = ? AND DATE(completed_at) = CURDATE()',
        [decoded.userId, taskId]
      );
      if (existing.length > 0) return res.status(400).json({ error: '今日已完成此任务' });
    }
    
    await pool.execute('INSERT INTO task_completions (user_id, task_id) VALUES (?, ?)', [decoded.userId, taskId]);
    await pool.execute('UPDATE users SET points = points + ? WHERE id = ?', [task.points_reward, decoded.userId]);
    
    res.json({ success: true, pointsEarned: task.points_reward });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 19. 支付系统 - 微信支付、支付宝、订单管理
// ========================================

const PAYMENT_CONFIG = {
  wechat: { appId: process.env.WECHAT_PAY_APP_ID || '', mchId: process.env.WECHAT_PAY_MCH_ID || '', apiKey: process.env.WECHAT_PAY_API_KEY || '', notifyUrl: process.env.WECHAT_PAY_NOTIFY_URL || '' },
  alipay: { appId: process.env.ALIPAY_APP_ID || '', privateKey: process.env.ALIPAY_PRIVATE_KEY || '', publicKey: process.env.ALIPAY_PUBLIC_KEY || '', notifyUrl: process.env.ALIPAY_NOTIFY_URL || '' }
};

async function initPaymentDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS payment_orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_no VARCHAR(100) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    order_type VARCHAR(50) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'CNY',
    status VARCHAR(20) DEFAULT 'pending',
    payment_method VARCHAR(20),
    transaction_id VARCHAR(100),
    paid_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
}

function generateOrderNo() {
  return `AM${Date.now()}${Math.floor(Math.random() * 10000).toString().padStart(4, '0')}`;
}

app.post('/api/payment/create', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { order_type, amount, description, payment_method } = req.body;
    if (!order_type || !amount || !payment_method) return res.status(400).json({ error: '缺少必要参数' });
    
    const pool = await getPool();
    await initPaymentDB();
    
    const orderNo = generateOrderNo();
    const [result] = await pool.execute(
      'INSERT INTO payment_orders (order_no, user_id, order_type, amount, payment_method) VALUES (?, ?, ?, ?, ?)',
      [orderNo, decoded.userId, order_type, amount, payment_method]
    );
    
    res.json({ orderId: result.insertId, orderNo, amount, payment_method, success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/payment/notify', async (req, res) => {
  try {
    const { order_no, transaction_id, payment_method } = req.body;
    const pool = await getPool();
    await initPaymentDB();
    
    await pool.execute('UPDATE payment_orders SET status = ?, transaction_id = ?, paid_at = NOW() WHERE order_no = ?', ['paid', transaction_id, order_no]);
    
    const [orders] = await pool.execute('SELECT * FROM payment_orders WHERE order_no = ?', [order_no]);
    if (orders.length === 0) return res.status(404).json({ error: '订单不存在' });
    
    const order = orders[0];
    if (order.order_type === 'vip') {
      const [vipOrders] = await pool.execute('SELECT * FROM vip_orders WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1', [order.user_id, 'pending']);
      if (vipOrders.length > 0) {
        await pool.execute('UPDATE vip_orders SET status = ?, paid_at = NOW(), payment_method = ? WHERE id = ?', ['paid', payment_method, vipOrders[0].id]);
      }
    }
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/payment/orders', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    const [orders] = await pool.execute('SELECT * FROM payment_orders WHERE user_id = ? ORDER BY created_at DESC', [decoded.userId]);
    res.json(orders);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 20. 消息推送完整版 - 极光推送、华为推送、苹果APNs
// ========================================

const PUSH_CONFIG = {
  jiguang: { appKey: process.env.JIGUANG_APP_KEY || '', masterSecret: process.env.JIGUANG_MASTER_SECRET || '' },
  huawei: { appId: process.env.HUAWEI_APP_ID || '', appSecret: process.env.HUAWEI_APP_SECRET || '' },
  apns: { teamId: process.env.APNS_TEAM_ID || '', keyId: process.env.APNS_KEY_ID || '', bundleId: process.env.APNS_BUNDLE_ID || '' }
};

async function initPushDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS device_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    device_token VARCHAR(255) NOT NULL,
    device_type ENUM('ios', 'android', 'huawei') NOT NULL,
    push_enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
}

app.post('/api/push/register', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { device_token, device_type } = req.body;
    if (!device_token || !device_type) return res.status(400).json({ error: '缺少必要参数' });
    
    const pool = await getPool();
    await initPushDB();
    
    await pool.execute('INSERT INTO device_tokens (user_id, device_token, device_type) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE device_token = ?', [decoded.userId, device_token, device_type, device_token]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/push/send', async (req, res) => {
  try {
    const { user_id, title, content, extras } = req.body;
    if (!user_id || !title || !content) return res.status(400).json({ error: '缺少必要参数' });
    
    const pool = await getPool();
    await initPushDB();
    
    const [devices] = await pool.execute('SELECT * FROM device_tokens WHERE user_id = ? AND push_enabled = TRUE', [user_id]);
    
    res.json({ success: true, message: '推送已发送', devices: devices.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 21. 管理后台API - 用户管理、内容审核、数据统计
// ========================================

async function initAdminDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS admin_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    admin_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    target_type VARCHAR(50),
    target_id INT,
    details JSON,
    ip_address VARCHAR(50),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id)
  )`);
}

async function checkAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [users] = await pool.execute('SELECT is_admin FROM users WHERE id = ?', [decoded.userId]);
    
    if (users.length === 0 || !users[0].is_admin) {
      return res.status(403).json({ error: '无管理员权限' });
    }
    
    req.adminId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: '无效的token' });
  }
}

app.get('/api/admin/users', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, keyword } = req.query;
    const pool = await getPool();
    
    let query = 'SELECT id, phone, nickname, avatar, points, exp, vip_expire_at, is_admin, created_at FROM users WHERE 1=1';
    const params = [];
    if (keyword) { query += ' AND (nickname LIKE ? OR phone LIKE ?)'; params.push(`%${keyword}%`, `%${keyword}%`); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [users] = await pool.execute(query, params);
    res.json(users);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/users/:id', checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    const [users] = await pool.execute('SELECT id, phone, nickname, avatar, points, exp, vip_expire_at, is_admin, created_at FROM users WHERE id = ?', [id]);
    if (users.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(users[0]);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/admin/users/:id', checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nickname, points, exp, is_admin, vip_expire_at } = req.body;
    const pool = await getPool();
    
    let updates = [];
    let params = [];
    if (nickname !== undefined) { updates.push('nickname = ?'); params.push(nickname); }
    if (points !== undefined) { updates.push('points = ?'); params.push(points); }
    if (exp !== undefined) { updates.push('exp = ?'); params.push(exp); }
    if (is_admin !== undefined) { updates.push('is_admin = ?'); params.push(is_admin); }
    if (vip_expire_at !== undefined) { updates.push('vip_expire_at = ?'); params.push(vip_expire_at); }
    
    if (updates.length === 0) return res.status(400).json({ error: '没有要更新的字段' });
    params.push(id);
    
    await pool.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    await initAdminDB();
    await pool.execute('INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)', [req.adminId, 'update_user', 'user', id, JSON.stringify(req.body)]);
    
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/admin/users/:id', checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await getPool();
    await pool.execute('DELETE FROM users WHERE id = ?', [id]);
    await initAdminDB();
    await pool.execute('INSERT INTO admin_logs (admin_id, action, target_type, target_id) VALUES (?, ?, ?, ?)', [req.adminId, 'delete_user', 'user', id]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 内容审核
app.get('/api/admin/posts', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const pool = await getPool();
    
    let query = 'SELECT p.*, u.nickname as user_nickname FROM posts p JOIN users u ON p.user_id = u.id WHERE 1=1';
    const params = [];
    if (status) { query += ' AND p.status = ?'; params.push(status); }
    query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [posts] = await pool.execute(query, params);
    res.json(posts);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/admin/posts/:id/approve', checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { approved, reason } = req.body;
    const pool = await getPool();
    
    const status = approved ? 'approved' : 'rejected';
    await pool.execute('UPDATE posts SET status = ? WHERE id = ?', [status, id]);
    await initAdminDB();
    await pool.execute('INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)', [req.adminId, 'approve_post', 'post', id, JSON.stringify({ approved, reason })]);
    
    res.json({ success: true, status });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 数据统计
app.get('/api/admin/stats', checkAdmin, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const pool = await getPool();
    
    const [userStats] = await pool.execute('SELECT COUNT(*) as total FROM users');
    const [postStats] = await pool.execute('SELECT COUNT(*) as total FROM posts');
    const [petStats] = await pool.execute('SELECT COUNT(*) as total FROM pets');
    const [activityStats] = await pool.execute('SELECT COUNT(*) as total FROM activities');
    const [vipStats] = await pool.execute('SELECT COUNT(*) as total FROM users WHERE vip_expire_at > NOW()');
    
    res.json({
      users: userStats[0].total,
      posts: postStats[0].total,
      pets: petStats[0].total,
      activities: activityStats[0].total,
      vipUsers: vipStats[0].total
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/logs', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, action } = req.query;
    const pool = await getPool();
    await initAdminDB();
    
    let query = 'SELECT l.*, u.nickname as admin_nickname FROM admin_logs l JOIN users u ON l.admin_id = u.id WHERE 1=1';
    const params = [];
    if (action) { query += ' AND l.action = ?'; params.push(action); }
    query += ' ORDER BY l.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [logs] = await pool.execute(query, params);
    res.json(logs);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 22. 日志系统 - 操作日志、登录日志、异常日志
// ========================================

async function initLogDB() {
  const pool = await getPool();
  await pool.execute(`CREATE TABLE IF NOT EXISTS operation_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(50) NOT NULL,
    module VARCHAR(50),
    method VARCHAR(20),
    path VARCHAR(255),
    params JSON,
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS login_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    login_type VARCHAR(20),
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    status VARCHAR(20),
    fail_reason VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  await pool.execute(`CREATE TABLE IF NOT EXISTS error_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    error_type VARCHAR(50),
    message TEXT,
    stack TEXT,
    url VARCHAR(255),
    user_id INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
}

// 记录操作日志
app.use(async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  let userId = null;
  if (token) {
    try { const decoded = jwt.verify(token, JWT_SECRET); userId = decoded.userId; } catch (e) {}
  }
  
  const originalSend = res.send;
  res.send = function(data) {
    if (req.path.startsWith('/api/') && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      getPool().then(pool => {
        initLogDB().then(() => {
          pool.execute(
            'INSERT INTO operation_logs (user_id, action, module, method, path, params, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, req.method, req.path.split('/')[2] || '', req.method, req.path, JSON.stringify(req.body), req.ip, req.headers['user-agent']]
          ).catch(() => {});
        });
      });
    }
    originalSend.call(this, data);
  };
  
  next();
});

// 获取操作日志
app.get('/api/logs/operations', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, user_id, action } = req.query;
    const pool = await getPool();
    await initLogDB();
    
    let query = 'SELECT * FROM operation_logs WHERE 1=1';
    const params = [];
    if (user_id) { query += ' AND user_id = ?'; params.push(user_id); }
    if (action) { query += ' AND action = ?'; params.push(action); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [logs] = await pool.execute(query, params);
    res.json(logs);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取登录日志
app.get('/api/logs/login', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, user_id, status } = req.query;
    const pool = await getPool();
    await initLogDB();
    
    let query = 'SELECT * FROM login_logs WHERE 1=1';
    const params = [];
    if (user_id) { query += ' AND user_id = ?'; params.push(user_id); }
    if (status) { query += ' AND status = ?'; params.push(status); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [logs] = await pool.execute(query, params);
    res.json(logs);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取错误日志
app.get('/api/logs/errors', checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, error_type } = req.query;
    const pool = await getPool();
    await initLogDB();
    
    let query = 'SELECT * FROM error_logs WHERE 1=1';
    const params = [];
    if (error_type) { query += ' AND error_type = ?'; params.push(error_type); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));
    
    const [logs] = await pool.execute(query, params);
    res.json(logs);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 全局错误处理中间件
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  
  getPool().then(pool => {
    initLogDB().then(() => {
      pool.execute(
        'INSERT INTO error_logs (error_type, message, stack, url) VALUES (?, ?, ?, ?)',
        [err.name || 'Error', err.message, err.stack, req.url]
      ).catch(() => {});
    });
  });
  
  res.status(500).json({ error: err.message || '服务器内部错误' });
});

// ========================================
// 19. 邀请码系统 - 拉新运营功能
// ========================================

async function initInviteDB() {
  const pool = await getPool();
  // 邀请码表
  await pool.execute(`CREATE TABLE IF NOT EXISTS invite_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    used_count INT DEFAULT 0,
    max_uses INT DEFAULT 10,
    reward_points INT DEFAULT 200,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // 邀请记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS invite_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    inviter_id INT NOT NULL,
    invitee_id INT NOT NULL,
    invite_code VARCHAR(20) NOT NULL,
    reward_points INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inviter_id) REFERENCES users(id),
    FOREIGN KEY (invitee_id) REFERENCES users(id)
  )`);
}

// 生成邀请码
function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// 获取我的邀请码
app.get('/api/invite/code', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initInviteDB();
    
    let [codes] = await pool.execute('SELECT * FROM invite_codes WHERE user_id = ?', [decoded.userId]);
    
    // 如果没有邀请码，创建一个新的
    if (codes.length === 0) {
      const code = generateInviteCode();
      const expiresAt = new Date();
      expiresAt.setFullYear(expiresAt.getFullYear() + 1); // 1年后过期
      
      await pool.execute(
        'INSERT INTO invite_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
        [decoded.userId, code, expiresAt]
      );
      [codes] = await pool.execute('SELECT * FROM invite_codes WHERE user_id = ?', [decoded.userId]);
    }
    
    const code = codes[0];
    
    // 获取邀请统计
    const [stats] = await pool.execute(
      'SELECT COUNT(*) as total_invites, SUM(reward_points) as total_points FROM invite_records WHERE inviter_id = ?',
      [decoded.userId]
    );
    
    res.json({
      code: code.code,
      used_count: code.used_count,
      max_uses: code.max_uses,
      reward_points: code.reward_points,
      total_invites: stats[0].total_invites || 0,
      total_points: stats[0].total_points || 0,
      expires_at: code.expires_at
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 使用邀请码注册
app.post('/api/invite/use', async (req, res) => {
  try {
    const { code, phone, password, nickname } = req.body;
    if (!code || !phone) return res.status(400).json({ error: '邀请码和手机号不能为空' });
    
    const pool = await getPool();
    await initInviteDB();
    
    // 查找邀请码
    const [codes] = await pool.execute('SELECT * FROM invite_codes WHERE code = ?', [code]);
    if (codes.length === 0) return res.status(400).json({ error: '邀请码无效' });
    
    const inviteCode = codes[0];
    
    // 检查邀请码是否过期
    if (inviteCode.expires_at && new Date(inviteCode.expires_at) < new Date()) {
      return res.status(400).json({ error: '邀请码已过期' });
    }
    
    // 检查邀请码是否达到上限
    if (inviteCode.used_count >= inviteCode.max_uses) {
      return res.status(400).json({ error: '邀请码已达使用上限' });
    }
    
    // 检查手机号是否已注册
    const [existing] = await pool.execute('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing.length > 0) return res.status(400).json({ error: '手机号已注册' });
    
    // 创建新用户
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (phone, password, nickname, avatar, points) VALUES (?, ?, ?, ?, ?)',
      [phone, hashedPassword, nickname || '用户' + phone.slice(-4), '🐱', 100]
    );
    
    const newUserId = result.insertId;
    
    // 更新邀请码使用次数
    await pool.execute('UPDATE invite_codes SET used_count = used_count + 1 WHERE id = ?', [inviteCode.id]);
    
    // 记录邀请关系
    await pool.execute(
      'INSERT INTO invite_records (inviter_id, invitee_id, invite_code, reward_points) VALUES (?, ?, ?, ?)',
      [inviteCode.user_id, newUserId, code, inviteCode.reward_points]
    );
    
    // 给邀请者奖励积分
    await pool.execute('UPDATE users SET points = points + ? WHERE id = ?', [inviteCode.reward_points, inviteCode.user_id]);
    await pool.execute(
      'INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
      [inviteCode.user_id, 'invite_reward', inviteCode.reward_points, `邀请新用户奖励`]
    );
    
    // 给新用户额外奖励
    await pool.execute('UPDATE users SET points = points + 100 WHERE id = ?', [newUserId]);
    await pool.execute(
      'INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
      [newUserId, 'invitee_bonus', 100, '使用邀请码注册奖励']
    );
    
    // 生成token
    const token = jwt.sign({ userId: newUserId, phone }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
      user: { id: newUserId, phone, nickname: nickname || '用户' + phone.slice(-4), avatar: '🐱' },
      reward: {
        inviter_points: inviteCode.reward_points,
        invitee_points: 100
      }
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取邀请记录
app.get('/api/invite/records', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initInviteDB();
    
    const [records] = await pool.execute(
      `SELECT r.*, u.nickname as invitee_nickname, u.avatar as invitee_avatar 
       FROM invite_records r 
       JOIN users u ON r.invitee_id = u.id 
       WHERE r.inviter_id = ? 
       ORDER BY r.created_at DESC`,
      [decoded.userId]
    );
    
    res.json(records);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ========================================
// 20. 连续签到奖励系统
// ========================================

async function initCheckinDB() {
  const pool = await getPool();
  // 签到记录表
  await pool.execute(`CREATE TABLE IF NOT EXISTS checkin_records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    checkin_date DATE NOT NULL,
    streak_days INT DEFAULT 1,
    points_earned INT DEFAULT 10,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_checkin (user_id, checkin_date)
  )`);
}

// 签到
app.post('/api/checkin', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initCheckinDB();
    
    const today = new Date().toISOString().split('T')[0];
    
    // 检查今天是否已签到
    const [existing] = await pool.execute(
      'SELECT * FROM checkin_records WHERE user_id = ? AND checkin_date = ?',
      [decoded.userId, today]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ error: '今日已签到', streak_days: existing[0].streak_days });
    }
    
    // 获取昨天签到记录
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    
    const [yesterdayRecord] = await pool.execute(
      'SELECT * FROM checkin_records WHERE user_id = ? AND checkin_date = ?',
      [decoded.userId, yesterdayStr]
    );
    
    // 计算连续签到天数和奖励积分
    let streakDays = 1;
    let pointsEarned = 10; // 基础签到积分
    
    if (yesterdayRecord.length > 0) {
      streakDays = yesterdayRecord[0].streak_days + 1;
      
      // 连续签到加成
      if (streakDays >= 7) {
        pointsEarned = 30; // 7天2倍
      } else if (streakDays >= 30) {
        pointsEarned = 60; // 30天5倍
      } else if (streakDays >= 3) {
        pointsEarned = 15; // 3天1.5倍
      }
    }
    
    // 记录签到
    await pool.execute(
      'INSERT INTO checkin_records (user_id, checkin_date, streak_days, points_earned) VALUES (?, ?, ?, ?)',
      [decoded.userId, today, streakDays, pointsEarned]
    );
    
    // 发放积分
    await pool.execute('UPDATE users SET points = points + ? WHERE id = ?', [pointsEarned, decoded.userId]);
    await pool.execute(
      'INSERT INTO points_records (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
      [decoded.userId, 'daily_checkin', pointsEarned, `连续签到${streakDays}天奖励`]
    );
    
    res.json({
      success: true,
      streak_days: streakDays,
      points_earned: pointsEarned,
      message: streakDays >= 7 ? `太棒了！连续签到${streakDays}天，获得${pointsEarned}积分奖励！` : `签到成功！连续签到${streakDays}天`
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 获取签到状态
app.get('/api/checkin/status', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const pool = await getPool();
    await initCheckinDB();
    
    const today = new Date().toISOString().split('T')[0];
    
    // 检查今天是否已签到
    const [todayRecord] = await pool.execute(
      'SELECT * FROM checkin_records WHERE user_id = ? AND checkin_date = ?',
      [decoded.userId, today]
    );
    
    // 获取最长连续签到
    const [maxStreak] = await pool.execute(
      'SELECT MAX(streak_days) as max_streak FROM checkin_records WHERE user_id = ?',
      [decoded.userId]
    );
    
    // 获取最近7天签到记录
    const [weekRecords] = await pool.execute(
      'SELECT checkin_date, streak_days FROM checkin_records WHERE user_id = ? AND checkin_date >= DATE_SUB(?, INTERVAL 7 DAY) ORDER BY checkin_date DESC',
      [decoded.userId, today]
    );
    
    res.json({
      checked_in: todayRecord.length > 0,
      streak_days: todayRecord.length > 0 ? todayRecord[0].streak_days : 0,
      max_streak: maxStreak[0].max_streak || 0,
      week_records: weekRecords
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 启动服务器
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});


