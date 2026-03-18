# deps 阶段在 CI 原生平台安装依赖，避免 QEMU 下 npm install 缓慢
# 所有依赖均为纯 JS（无 native addon），node_modules 可跨平台复用
FROM --platform=$BUILDPLATFORM node:20-alpine AS deps

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

# 最终镜像使用目标平台的 Node.js 运行时
FROM node:20-alpine

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules

# 复制源代码
COPY . .

EXPOSE 3000

# 以非root用户运行，减小安全风险
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

CMD ["npm", "start"]
