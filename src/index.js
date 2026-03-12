const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'amao-jwt-secret-2026';

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
    pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'amao',
      password: process.env.DB_PASSWORD || 'Amao2026!',
      database: process.env.DB_NAME || 'amao',
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

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
