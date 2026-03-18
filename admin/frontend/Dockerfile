# builder 阶段固定跑在 CI 原生平台（amd64），避免 QEMU 模拟 ARM64 导致 npm install 极慢
# dist/ 是纯静态文件，与 CPU 架构无关，可安全跨平台复制
FROM --platform=$BUILDPLATFORM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# 最终镜像使用目标平台的 nginx，仅复制静态文件
FROM nginx:alpine

WORKDIR /usr/share/nginx/html

RUN rm -rf ./*

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist ./

RUN echo "Build completed at: $(date)" > build-info.txt

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
