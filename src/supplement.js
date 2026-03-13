/**
 * 补充API - 用于修复测试用例中缺失的功能
 */

module.exports = function supplementAPI(app, { getPool, jwt, bcrypt, JWT_SECRET }) {
  
  // ==================== 用户模块 ====================
  
  // 登录验证码（占位）
  app.get('/api/auth/captcha', async (req, res) => {
    const { phone } = req.query;
    if (!phone || phone.length !== 11) {
      return res.status(400).json({ error: '手机号格式错误' });
    }
    res.json({ captcha: '123456', message: '验证码已发送（测试环境）' });
  });

  // 获取指定用户信息
  app.get('/api/users/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const pool = await getPool();
      const [users] = await pool.execute(
        'SELECT id, nickname, avatar, location, created_at FROM users WHERE id = ?',
        [id]
      );
      if (users.length === 0) {
        return res.status(404).json({ error: '用户不存在' });
      }
      res.json(users[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 修改密码
  app.post('/api/user/password', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { oldPassword, newPassword } = req.body;
      if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: '请提供旧密码和新密码' });
      }
      if (newPassword.length < 6) {
        return res.status(400).json({ error: '新密码至少6位' });
      }
      const pool = await getPool();
      const [users] = await pool.execute('SELECT password FROM users WHERE id = ?', [decoded.userId]);
      const validPassword = await bcrypt.compare(oldPassword, users[0].password);
      if (!validPassword) {
        return res.status(401).json({ error: '原密码错误' });
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, decoded.userId]);
      res.json({ success: true, message: '密码修改成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 宠物列表（支持分页）
  app.get('/api/pets', async (req, res) => {
    try {
      const { page = 1, pageSize = 10, species, gender, minAge, maxAge, keyword } = req.query;
      const pool = await getPool();
      let query = 'SELECT * FROM pets WHERE 1=1';
      const params = [];
      if (species) { query += ' AND species = ?'; params.push(species); }
      if (gender) { query += ' AND gender = ?'; params.push(gender); }
      if (minAge) { query += ' AND age >= ?'; params.push(parseInt(minAge)); }
      if (maxAge) { query += ' AND age <= ?'; params.push(parseInt(maxAge)); }
      if (keyword) { query += ' AND (name LIKE ? OR breed LIKE ?)'; params.push('%' + keyword + '%', '%' + keyword + '%'); }
      query += ' ORDER BY created_at DESC LIMIT ' + parseInt(pageSize) + ' OFFSET ' + ((parseInt(page) - 1) * parseInt(pageSize));
      const [pets] = await pool.execute(query, params);
      res.json(pets);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 帖子列表（支持分页）
  app.get('/api/posts', async (req, res) => {
    try {
      const { page = 1, pageSize = 10, category, petId, userId } = req.query;
      const pool = await getPool();
      let query = 'SELECT p.*, u.nickname as user_nickname, u.avatar as user_avatar FROM posts p LEFT JOIN users u ON p.user_id = u.id WHERE 1=1';
      const params = [];
      if (category) { query += ' AND p.category = ?'; params.push(category); }
      if (petId) { query += ' AND p.pet_id = ?'; params.push(petId); }
      if (userId) { query += ' AND p.user_id = ?'; params.push(userId); }
      query += ' ORDER BY p.created_at DESC LIMIT ' + parseInt(pageSize) + ' OFFSET ' + ((parseInt(page) - 1) * parseInt(pageSize));
      const [posts] = await pool.execute(query, params);
      res.json(posts);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 活动列表（支持分页）
  app.get('/api/activities', async (req, res) => {
    try {
      const { page = 1, pageSize = 10, type, status } = req.query;
      const pool = await getPool();
      let query = 'SELECT * FROM activities WHERE 1=1';
      const params = [];
      if (type) { query += ' AND type = ?'; params.push(type); }
      if (status) { query += ' AND status = ?'; params.push(status); }
      query += ' ORDER BY date ASC LIMIT ' + parseInt(pageSize) + ' OFFSET ' + ((parseInt(page) - 1) * parseInt(pageSize));
      const [activities] = await pool.execute(query, params);
      res.json(activities);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 活动详情
  app.get('/api/activities/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const pool = await getPool();
      const [activities] = await pool.execute('SELECT * FROM activities WHERE id = ?', [id]);
      if (activities.length === 0) {
        return res.status(404).json({ error: '活动不存在' });
      }
      res.json(activities[0]);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 更新帖子
  app.put('/api/posts/:id', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const { content, images, category, location } = req.body;
      const pool = await getPool();
      const [posts] = await pool.execute('SELECT user_id FROM posts WHERE id = ?', [id]);
      if (posts.length === 0) {
        return res.status(404).json({ error: '帖子不存在' });
      }
      if (posts[0].user_id !== decoded.userId) {
        return res.status(403).json({ error: '无权限修改此帖子' });
      }
      const updates = [];
      const params = [];
      if (content !== undefined) { updates.push('content = ?'); params.push(content); }
      if (images !== undefined) { updates.push('images = ?'); params.push(images || null); }
      if (category !== undefined) { updates.push('category = ?'); params.push(category); }
      if (location !== undefined) { updates.push('location = ?'); params.push(location); }
      if (updates.length === 0) {
        return res.status(400).json({ error: '没有要更新的内容' });
      }
      params.push(id);
      await pool.execute('UPDATE posts SET ' + updates.join(', ') + ' WHERE id = ?', params);
      res.json({ success: true, message: '帖子更新成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 删除帖子
  app.delete('/api/posts/:id', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [posts] = await pool.execute('SELECT user_id FROM posts WHERE id = ?', [id]);
      if (posts.length === 0) {
        return res.status(404).json({ error: '帖子不存在' });
      }
      if (posts[0].user_id !== decoded.userId) {
        return res.status(403).json({ error: '无权限删除此帖子' });
      }
      await pool.execute('DELETE FROM posts WHERE id = ?', [id]);
      res.json({ success: true, message: '帖子删除成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 更新活动
  app.put('/api/activities/:id', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const { title, description, location, date, time, max_participants } = req.body;
      const pool = await getPool();
      const [activities] = await pool.execute('SELECT user_id FROM activities WHERE id = ?', [id]);
      if (activities.length === 0) {
        return res.status(404).json({ error: '活动不存在' });
      }
      if (activities[0].user_id !== decoded.userId) {
        return res.status(403).json({ error: '无权限修改此活动' });
      }
      const updates = [];
      const params = [];
      if (title !== undefined) { updates.push('title = ?'); params.push(title || null); }
      if (description !== undefined) { updates.push('description = ?'); params.push(description || null); }
      if (location !== undefined) { updates.push('location = ?'); params.push(location || null); }
      if (date !== undefined) { updates.push('date = ?'); params.push(date || null); }
      if (time !== undefined) { updates.push('time = ?'); params.push(time || null); }
      if (max_participants !== undefined) { updates.push('max_participants = ?'); params.push(max_participants || null); }
      if (updates.length === 0) {
        return res.status(400).json({ error: '没有要更新的内容' });
      }
      params.push(id);
      await pool.execute('UPDATE activities SET ' + updates.join(', ') + ' WHERE id = ?', params);
      res.json({ success: true, message: '活动更新成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 删除活动
  app.delete('/api/activities/:id', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [activities] = await pool.execute('SELECT user_id FROM activities WHERE id = ?', [id]);
      if (activities.length === 0) {
        return res.status(404).json({ error: '活动不存在' });
      }
      if (activities[0].user_id !== decoded.userId) {
        return res.status(403).json({ error: '无权限删除此活动' });
      }
      await pool.execute('DELETE FROM activities WHERE id = ?', [id]);
      res.json({ success: true, message: '活动删除成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 评论列表（修复版）
  app.get('/api/posts/:postId/comments', async (req, res) => {
    try {
      const { postId } = req.params;
      const { limit = 20, offset = 0 } = req.query;
      const pool = await getPool();
      
      const limitVal = parseInt(limit) || 20;
      const offsetVal = parseInt(offset) || 0;
      
      const sql = 'SELECT c.*, u.nickname, u.avatar as user_avatar, (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) as likes_count FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ' + postId + ' AND c.parent_id IS NULL ORDER BY c.created_at DESC LIMIT ' + limitVal + ' OFFSET ' + offsetVal;
      
      const [comments] = await pool.query(sql);
      
      // 获取回复
      for (const comment of comments) {
        const replySql = 'SELECT c.*, u.nickname, u.avatar as user_avatar FROM comments c JOIN users u ON c.user_id = u.id WHERE c.parent_id = ' + comment.id + ' ORDER BY c.created_at ASC';
        const [replies] = await pool.query(replySql);
        comment.replies = replies;
      }
      
      res.json(comments);
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 删除评论
  app.delete('/api/comments/:id', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [comments] = await pool.execute('SELECT user_id, post_id FROM comments WHERE id = ?', [id]);
      if (comments.length === 0) {
        return res.status(404).json({ error: '评论不存在' });
      }
      if (comments[0].user_id !== decoded.userId) {
        return res.status(403).json({ error: '无权限删除此评论' });
      }
      await pool.execute('DELETE FROM comments WHERE id = ? OR parent_id = ?', [id, id]);
      await pool.execute('UPDATE posts SET comments_count = GREATEST(comments_count - 1, 0) WHERE id = ?', [comments[0].post_id]);
      res.json({ success: true, message: '评论删除成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 评论点赞
  app.post('/api/comments/:id/like', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      
      const [existing] = await pool.execute('SELECT id FROM comment_likes WHERE user_id = ? AND comment_id = ?', [decoded.userId, id]);
      
      if (existing.length > 0) {
        await pool.execute('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?', [decoded.userId, id]);
        await pool.execute('UPDATE comments SET likes_count = GREATEST(likes_count - 1, 0) WHERE id = ?', [id]);
        res.json({ success: true, liked: false });
      } else {
        await pool.execute('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)', [decoded.userId, id]);
        await pool.execute('UPDATE comments SET likes_count = likes_count + 1 WHERE id = ?', [id]);
        res.json({ success: true, liked: true });
      }
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 发布帖子
  app.post('/api/posts', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { content, images, video, cover, category, location, petId } = req.body;
      if (!content) {
        return res.status(400).json({ error: '内容不能为空' });
      }
      const pool = await getPool();
      const [result] = await pool.execute(
        'INSERT INTO posts (user_id, content, images, video, cover, category, location, pet_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [decoded.userId, content, images || null, video || null, cover || null, category || 'daily', location || null, petId || null]
      );
      res.json({ id: result.insertId, success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 发布活动
  app.post('/api/activities', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags } = req.body;
      if (!title) {
        return res.status(400).json({ error: '标题不能为空' });
      }
      const pool = await getPool();
      const [result] = await pool.execute(
        'INSERT INTO activities (user_id, title, description, location, address, lat, lng, date, time, fee, max_participants, images, type, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [decoded.userId, title, description || null, location || null, address || null, lat || null, lng || null, date || null, time || null, fee || '免费', max_participants || null, images ? JSON.stringify(images) : '[]', type || 'play', tags ? JSON.stringify(tags) : '[]']
      );
      res.json({ id: result.insertId, success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 活动报名
  app.post('/api/activities/:id/register', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [activities] = await pool.execute('SELECT * FROM activities WHERE id = ?', [id]);
      if (activities.length === 0) {
        return res.status(404).json({ error: '活动不存在' });
      }
      const [existing] = await pool.execute('SELECT id FROM activity_registrations WHERE activity_id = ? AND user_id = ?', [id, decoded.userId]);
      if (existing.length > 0) {
        return res.status(400).json({ error: '您已报名此活动' });
      }
      await pool.execute('INSERT INTO activity_registrations (activity_id, user_id, status) VALUES (?, ?, ?)', [id, decoded.userId, 'registered']);
      await pool.execute('UPDATE activities SET participants_count = participants_count + 1 WHERE id = ?', [id]);
      res.json({ success: true, message: '报名成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 取消报名
  app.delete('/api/activities/:id/register', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [result] = await pool.execute('DELETE FROM activity_registrations WHERE activity_id = ? AND user_id = ?', [id, decoded.userId]);
      if (result.affectedRows === 0) {
        return res.status(400).json({ error: '您未报名此活动' });
      }
      await pool.execute('UPDATE activities SET participants_count = GREATEST(participants_count - 1, 0) WHERE id = ?', [id]);
      res.json({ success: true, message: '取消报名成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 活动签到
  app.post('/api/activities/:id/checkin', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { id } = req.params;
      const pool = await getPool();
      const [registrations] = await pool.execute('SELECT * FROM activity_registrations WHERE activity_id = ? AND user_id = ?', [id, decoded.userId]);
      if (registrations.length === 0) {
        return res.status(400).json({ error: '您未报名此活动' });
      }
      if (registrations[0].checked_in) {
        return res.status(400).json({ error: '您已签到' });
      }
      await pool.execute('UPDATE activity_registrations SET checked_in = TRUE WHERE id = ?', [registrations[0].id]);
      res.json({ success: true, message: '签到成功' });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  // 使用邀请码
  app.post('/api/invite/use', async (req, res) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (!token) return res.status(401).json({ error: '请先登录' });
      const decoded = jwt.verify(token, JWT_SECRET);
      const { code, phone } = req.body;
      if (!code || !phone) {
        return res.status(400).json({ error: '邀请码和手机号不能为空' });
      }
      const pool = await getPool();
      const [inviteCodes] = await pool.execute('SELECT * FROM invite_codes WHERE code = ?', [code]);
      if (inviteCodes.length === 0) {
        return res.status(400).json({ error: '邀请码无效' });
      }
      const inviteCode = inviteCodes[0];
      if (inviteCode.used_count >= inviteCode.max_uses) {
        return res.status(400).json({ error: '邀请码已达到使用上限' });
      }
      if (inviteCode.expires_at && new Date(inviteCode.expires_at) < new Date()) {
        return res.status(400).json({ error: '邀请码已过期' });
      }
      await pool.execute('UPDATE invite_codes SET used_count = used_count + 1 WHERE id = ?', [inviteCode.id]);
      await pool.execute('INSERT INTO invite_records (inviter_id, invitee_id, invite_code) VALUES (?, ?, ?)', [inviteCode.user_id, decoded.userId, code]);
      await pool.execute('UPDATE users SET points = points + ? WHERE id = ?', [inviteCode.reward_points || 200, decoded.userId]);
      res.json({ success: true, message: '邀请码使用成功', reward_points: inviteCode.reward_points || 200 });
    } catch (error) { res.status(500).json({ error: error.message }); }
  });

  console.log('✅ 补充API模块已加载');
};
