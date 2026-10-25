FROM php:8.2-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping libsqlite3-dev \
    && (docker-php-ext-install pdo_sqlite || true) \
    && rm -rf /var/lib/apt/lists/*

# Route every request to the front controller (generated paths have no real files).
RUN printf '<Directory /var/www/html>\n  AllowOverride None\n  FallbackResource /index.php\n</Directory>\n' \
    > /etc/apache2/conf-enabled/zz-router.conf \
    && printf 'ServerTokens Prod\nServerSignature Off\n' > /etc/apache2/conf-enabled/zz-quiet.conf

COPY app/ /var/www/app/
COPY public/ /var/www/html/
COPY bootstrap.php /var/www/bootstrap.php
COPY docker-entrypoint.sh /usr/local/bin/app-entrypoint

ENV APP_DATA=/var/www/data
RUN chmod +x /usr/local/bin/app-entrypoint && mkdir -p /var/www/data \
    && chown -R www-data:www-data /var/www/data

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/app-entrypoint"]
CMD ["apache2-foreground"]
