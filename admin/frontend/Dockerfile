FROM nginx:alpine

# 工作目录
WORKDIR /usr/share/nginx/html

# 复制静态文件
COPY public/*.html ./
COPY public/favicon.ico ./

# 添加自定义nginx配置
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 创建包含构建信息的文件，方便调试
RUN echo "Build completed at: $(date)" > build-info.txt

# 暴露端口
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
