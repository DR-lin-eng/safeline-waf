FROM alpine:3.22 AS reload-helper-build

RUN apk add --no-cache build-base

WORKDIR /src

COPY reload-helper.c ./

RUN cc -Os -s -o nginx-hup reload-helper.c

FROM openresty/openresty:alpine

COPY --from=reload-helper-build /src/nginx-hup /usr/local/bin/nginx-hup

RUN mkdir -p /usr/local/openresty/nginx/conf/default-certs \
  && mkdir -p /usr/local/openresty/nginx/logs \
  && touch /usr/local/openresty/nginx/logs/access.log /usr/local/openresty/nginx/logs/error.log

COPY default-certs/default.crt /usr/local/openresty/nginx/conf/default-certs/default.crt
COPY default-certs/default.key /usr/local/openresty/nginx/conf/default-certs/default.key

RUN chmod 644 /usr/local/openresty/nginx/conf/default-certs/default.crt \
  && chmod 644 /usr/local/openresty/nginx/conf/default-certs/default.key \
  && chown root:root /usr/local/bin/nginx-hup \
  && chmod 4755 /usr/local/bin/nginx-hup \
  && chmod 755 /usr/local/openresty/nginx/logs \
  && chmod 666 /usr/local/openresty/nginx/logs/access.log /usr/local/openresty/nginx/logs/error.log
