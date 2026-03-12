const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'amao-jwt-secret-2026';

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
let pool;
async function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: 'localhost',
      user: 'amao',
      password: 'Amao2026!',
      database: 'amao',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
  }
  return pool;
}

// Initialize database tables
async function initDB() {
  const pool = await getPool();
  
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT PRIMARY KEY AUTO_INCREMENT,
      phone VARCHAR(20) UNIQUE,
      nickname VARCHAR(50),
      avatar VARCHAR(255) DEFAULT '🐱',
      password VARCHAR(255),
      points INT DEFAULT 100,
      exp INT DEFAULT 0,
      vip_expire_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS pets (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT,
      name VARCHAR(50),
      breed VARCHAR(50),
      age INT,
      gender ENUM('公', '母'),
      avatar VARCHAR(255),
      personality VARCHAR(100),
      vaccinated BOOLEAN DEFAULT FALSE,
      certificate BOOLEAN DEFAULT FALSE,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS posts (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT,
      user_nickname VARCHAR(50),
      user_avatar VARCHAR(255),
      content TEXT,
      images JSON,
      category VARCHAR(50),
      location VARCHAR(100),
      likes INT DEFAULT 0,
      comments_count INT DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS activities (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT,
      title VARCHAR(100),
      description TEXT,
      location VARCHAR(100),
      address VARCHAR(255),
      lat DOUBLE,
      lng DOUBLE,
      date VARCHAR(50),
      time VARCHAR(20),
      fee VARCHAR(20) DEFAULT '免费',
      max_participants INT,
      participants_count INT DEFAULT 0,
      images JSON,
      type VARCHAR(50),
      tags JSON,
      status VARCHAR(20) DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  
  // Insert sample data if empty
  const [users] = await pool.execute('SELECT COUNT(*) as cnt FROM users');
  if (users[0].cnt === 0) {
    const hashedPassword = await bcrypt.hash('123456', 10);
    await pool.execute(`INSERT INTO users (phone, nickname, avatar, password, points, exp) VALUES 
      ('13800000001', '萌宠达人', '🐱', '${hashedPassword}', 100, 150),
      ('13800000002', '金毛爸爸', '🐕', '${hashedPassword}', 80, 80),
      ('13800000003', '布偶猫奴', '🐱', '${hashedPassword}', 150, 200)
    `);
    
    await pool.execute(`INSERT INTO pets (user_id, name, breed, age, gender, avatar, personality, vaccinated, certificate) VALUES 
      (1, '小橘', '中华田园猫', 1, '母', '🐱', '黏人', TRUE, TRUE),
      (2, '旺财', '金毛', 2, '公', '🐕', '活泼', TRUE, FALSE)
    `);
    
    await pool.execute(`INSERT INTO posts (user_id, user_nickname, user_avatar, content, category, location, likes) VALUES 
      (1, '萌宠达人', '🐱', '今天带小橘去公园遛弯，遇到了好多小伙伴！', 'play', '朝阳区·朝阳公园', 328),
      (2, '金毛爸爸', '🐕', '拆家小能手又开始了...我已经习惯了', 'funny', '海淀区', 189),
      (3, '布偶猫奴', '🐱', '主子今天终于肯让我拍照了！', 'cute', '', 512)
    `);
  }
  
  console.log('Database initialized');
}

initDB().catch(console.error);

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password, code } = req.body;
    const pool = await getPool();
    
    // If code exists, it's SMS login
    if (code) {
      const [users] = await pool.execute('SELECT * FROM users WHERE phone = ?', [phone]);
      if (users.length === 0) {
        const [result] = await pool.execute(
          'INSERT INTO users (phone, nickname, avatar, password) VALUES (?, ?, ?, ?)',
          [phone, '用户' + phone.slice(-4), '🐱', '']
        );
        const token = jwt.sign({ userId: result.insertId, phone }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ token, user: { id: result.insertId, phone, nickname: '用户' + phone.slice(-4), avatar: '🐱' } });
      }
      const token = jwt.sign({ userId: users[0].id, phone }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: users[0] });
    }
    
    const [users] = await pool.execute('SELECT * FROM users WHERE phone = ?', [phone]);
    if (users.length === 0) {
      return res.status(401).json({ error: '用户不存在' });
    }
    
    if (users[0].password && !await bcrypt.compare(password, users[0].password)) {
      return res.status(401).json({ error: '密码错误' });
    }
    
    const token = jwt.sign({ userId: users[0].id, phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: users[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password, nickname } = req.body;
    const pool = await getPool();
    
    const [existing] = await pool.execute('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing.length > 0) {
      return res.status(400).json({ error: '手机号已注册' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (phone, password, nickname, avatar) VALUES (?, ?, ?, ?)',
      [phone, hashedPassword, nickname || '用户' + phone.slice(-4), '🐱']
    );
    
    const token = jwt.sign({ userId: result.insertId, phone }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.insertId, phone, nickname, avatar: '🐱' } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SMS verification (simplified)
const smsCodes = new Map();
app.post('/api/auth/sms/send', async (req, res) => {
  const { phone } = req.body;
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  smsCodes.set(phone, { code, expires: Date.now() + 600000 });
  console.log(`SMS code for ${phone}: ${code}`);
  res.json({ success: true, message: '验证码已发送' });
});

app.post('/api/auth/sms/verify', async (req, res) => {
  const { phone, code } = req.body;
  const stored = smsCodes.get(phone);
  if (!stored || stored.code !== code || stored.expires < Date.now()) {
    return res.status(400).json({ error: '验证码错误或已过期' });
  }
  smsCodes.delete(phone);
  res.json({ valid: true });
});

// User routes
app.get('/api/users/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: '未登录' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const pool = await getPool();
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    
    if (users.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(users[0]);
  } catch (error) {
    res.status(401).json({ error: '无效的token' });
  }
});

// Pet routes
app.get('/api/pets', async (req, res) => {
  try {
    const pool = await getPool();
    const [pets] = await pool.execute('SELECT * FROM pets ORDER BY created_at DESC');
    res.json(pets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/pets/match', async (req, res) => {
  try {
    const { gender, breed } = req.query;
    const pool = await getPool();
    let query = 'SELECT * FROM pets WHERE 1=1';
    const params = [];
    
    if (gender) {
      query += ' AND gender != ?';
      params.push(gender);
    }
    if (breed) {
      query += ' AND breed = ?';
      params.push(breed);
    }
    
    const [pets] = await pool.execute(query, params);
    res.json(pets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/pets', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, breed, age, gender, avatar, personality, vaccinated, certificate, description } = req.body;
    
    const pool = await getPool();
    const [result] = await pool.execute(
      'INSERT INTO pets (user_id, name, breed, age, gender, avatar, personality, vaccinated, certificate, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [decoded.userId, name, breed, age, gender, avatar || '🐱', personality, vaccinated || false, certificate || false, description || '']
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Post routes
app.get('/api/posts', async (req, res) => {
  try {
    const pool = await getPool();
    const { category, limit = 20, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM posts';
    const params = [];
    
    if (category) {
      query += ' WHERE category = ?';
      params.push(category);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const [posts] = await pool.execute(query, params);
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { content, images, category, location } = req.body;
    
    const pool = await getPool();
    const [user] = await pool.execute('SELECT nickname, avatar FROM users WHERE id = ?', [decoded.userId]);
    
    const [result] = await pool.execute(
      'INSERT INTO posts (user_id, user_nickname, user_avatar, content, images, category, location) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [decoded.userId, user[0].nickname, user[0].avatar, content, JSON.stringify(images || []), category, location || '']
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const pool = await getPool();
    await pool.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Activity routes
app.get('/api/activities', async (req, res) => {
  try {
    const pool = await getPool();
    const [activities] = await pool.execute('SELECT * FROM activities ORDER BY created_at DESC');
    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/activities', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const { title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags } = req.body;
    
    const pool = await getPool();
    const [result] = await pool.execute(
      'INSERT INTO activities (user_id, title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [decoded.userId, title, description, location, address, lat, lng, date, time, fee || '免费', max_participants, JSON.stringify(images || []), type, JSON.stringify(tags || [])]
    );
    
    res.json({ id: result.insertId, success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
