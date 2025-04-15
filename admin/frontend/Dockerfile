FROM node:16-alpine as build-stage

WORKDIR /app

# 复制项目文件
COPY package*.json ./

# 安装依赖
RUN npm install

# 复制源代码
COPY . .

# 添加环境变量以忽略各种检查和警告
ENV NODE_ENV=production
ENV GENERATE_SOURCEMAP=false
ENV SKIP_PREFLIGHT_CHECK=true
ENV VUE_APP_API_URL=/safeline-admin-api

# 构建应用
RUN npm run build

# 生产环境阶段
FROM nginx:alpine as production-stage

# 从构建阶段复制构建产物
COPY --from=build-stage /app/dist /usr/share/nginx/html

# 添加自定义nginx配置
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 输出Nginx配置以供调试
RUN cat /etc/nginx/conf.d/default.conf

# 创建包含构建信息的文件，方便调试
RUN echo "Build completed at: $(date)" > /usr/share/nginx/html/build-info.txt

# 暴露端口
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
