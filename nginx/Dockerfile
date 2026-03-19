FROM openresty/openresty:alpine

RUN mkdir -p /usr/local/openresty/nginx/conf/default-certs \
  && mkdir -p /usr/local/openresty/nginx/logs \
  && touch /usr/local/openresty/nginx/logs/access.log /usr/local/openresty/nginx/logs/error.log

COPY default-certs/default.crt /usr/local/openresty/nginx/conf/default-certs/default.crt
COPY default-certs/default.key /usr/local/openresty/nginx/conf/default-certs/default.key

RUN chmod 644 /usr/local/openresty/nginx/conf/default-certs/default.crt \
  && chmod 644 /usr/local/openresty/nginx/conf/default-certs/default.key \
  && chmod 755 /usr/local/openresty/nginx/logs \
  && chmod 666 /usr/local/openresty/nginx/logs/access.log /usr/local/openresty/nginx/logs/error.log
