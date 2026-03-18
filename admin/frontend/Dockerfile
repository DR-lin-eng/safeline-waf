FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine

WORKDIR /usr/share/nginx/html

RUN rm -rf ./*

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist ./

RUN echo "Build completed at: $(date)" > build-info.txt

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
