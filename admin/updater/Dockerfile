FROM --platform=$BUILDPLATFORM node:20-alpine AS deps

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache docker-cli docker-cli-compose git

COPY --from=deps /app/node_modules ./node_modules
COPY . .

EXPOSE 3100

CMD ["npm", "start"]
