# 阿猫阿狗后端 Dockerfile
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制 package 文件
COPY package*.json ./

# 安装依赖
RUN npm ci --only=production

# 复制源码
COPY src/ ./src/

# 暴露端口
EXPOSE 3000

# 启动服务
CMD ["node", "src/index.js"]
