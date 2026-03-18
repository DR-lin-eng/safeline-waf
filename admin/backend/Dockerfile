FROM node:20-alpine

WORKDIR /app

# 安装依赖（利用层缓存）
COPY package*.json ./
RUN npm install --omit=dev

# 复制源代码
COPY . .

EXPOSE 3000

# 以非root用户运行，减小安全风险
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

CMD ["npm", "start"]
