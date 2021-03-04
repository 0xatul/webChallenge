FROM php:7.1.4-apache

EXPOSE 8023

RUN chown -R www-data:www-data /var/www/html/

