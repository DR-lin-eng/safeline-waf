FROM openresty/openresty:alpine

RUN mkdir -p /usr/local/openresty/nginx/conf/default-certs

COPY default-certs/default.crt /usr/local/openresty/nginx/conf/default-certs/default.crt
COPY default-certs/default.key /usr/local/openresty/nginx/conf/default-certs/default.key

RUN chmod 644 /usr/local/openresty/nginx/conf/default-certs/default.crt \
  && chmod 600 /usr/local/openresty/nginx/conf/default-certs/default.key
