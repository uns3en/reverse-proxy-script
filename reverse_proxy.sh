#!/bin/bash

#######################################
#                                     #
#   Reverse proxy automation script   #
#         Written by uns3en           #
#   Distributed under GPLv2 lisence   #
#                                     #
#######################################

#Begin print
clear
echo -e "\e[1m+++++++++++++++++++++++++++++++++\e[0m"
echo -e "\e[32m===Reverse Proxy domain config===\e[0m"
echo ' '
echo -e "\e[1;41mPROCEED AT YOUR OWN RISK\e[0m"

#Request domain name
echo 'Please enter the domain name (example.com or subdomain.example.com):'
read domain

#Secure WWW record?
echo -e "Do you want to secure \e[1;33mwww.$domain\e[0m? (y/n):"
read -n 1 -r www_req
echo ' '

#Switch print or terminate
if [ $www_req = "y" ]; then
echo -e "Securing \e[1;33m$domain\e[0m and \e[1;33mwww.$domain\e[0m..."
elif [ $www_req = "n" ]; then
echo -e "Securing \e[1;33m$domain\e[0m only..."
else
echo -e "\e[1;31mOnly y/n accepted.\e[0m"
echo -e "\e[1;31mExiting...\e[0m"
exit 0
fi
echo ' '

#Get upstream host IP and port
echo 'Please enter remote host IP (xxx.xxx.xxx.xxx):'
read upstream_ip
echo ' '
echo 'Please enter remote host port (1-65535):'
read upstream_port
echo ' '

#create files and symbolic link
mkdir -p /var/www/vhosts/$domain/httpdocs
touch /etc/nginx/sites-available/$domain.conf
ln -s /etc/nginx/sites-available/$domain.conf /etc/nginx/sites-enabled/$domain.conf
mkdir -p /var/www/vhosts/$domain/logs


#Set initial HTTP service to
echo 'Generating initial nginx config...'
if [ $www_req  = "y" ]; then
cat > /etc/nginx/sites-available/$domain.conf << CONF_0_YES
server {
     server_name $domain www.$domain;

CONF_0_YES
else
cat > /etc/nginx/sites-available/$domain.conf << CONF_0_NO
server {
     server_name $domain;

CONF_0_NO
fi
cat >> /etc/nginx/sites-available/$domain.conf << CONF_0
    location /.well-known {
        alias /var/www/vhosts/$domain/httpdocs/.well-known;
    }

    location / {
     proxy_pass_header Authorization;
     proxy_pass http://$upstream_ip:$upstream_port;
     proxy_set_header X-Real-IP \$remote_addr;
     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
     proxy_http_version 1.1;
     proxy_set_header Connection "";
     proxy_buffering off;
     client_max_body_size 0;
     proxy_read_timeout 36000s;
     proxy_redirect off;
     }

    listen 80;

    }
CONF_0

#Reload nginx after creating a basic server block
service nginx reload

#Generating SSL certificate
if [ $www_req = "y" ]; then
echo "Generating SSL certificate for $domain and www.$domain..."
certbot --nginx -d $domain -d www.$domain
else
echo "Generating SSL certificate for $domain"
certbot --nginx -d $domain
fi
echo 'SSL cert generated.'

#Set output, start config gen
echo 'Updating nginx .conf file...'
echo ' '
cat > /etc/nginx/sites-available/$domain.conf << CONF_1
server {

    # if you wish, you can use the below line for listen instead
    # which enables HTTP/2
    # requires nginx version >= 1.9.5

     listen 443 ssl http2;
CONF_1

#Server statement based on $www_req
if [ $www_req  = "y" ]; then
cat >> /etc/nginx/sites-available/$domain.conf <<CONF_2_YES
     server_name $domain www.$domain;
CONF_2_YES
else
cat >> /etc/nginx/sites-available/$domain.conf <<CONF_2_NO
     server_name $domain;
CONF_2_NO
fi
cat >> /etc/nginx/sites-available/$domain.conf <<CONF_3
    # Turn on OCSP stapling as recommended at
    # https://community.letsencrypt.org/t/integration-guide/13123
    # requires nginx version >= 1.3.7
     ssl_stapling on;
     ssl_stapling_verify on;

    #SSL security settings
     ssl_protocols TLSv1.2 TLSv1.3;
     ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
     ssl_prefer_server_ciphers on;
     ssl_ecdh_curve secp384r1;
     ssl_dhparam /etc/ssl/certs/dhparam.pem;
     ssl_session_timeout 10m;
     ssl_session_cache shared:SSL:10m;
     add_header X-Frame-Options "SAMEORIGIN" always;
     add_header Referrer-Policy same-origin;
     add_header X-Content-Type-Options nosniff;
     add_header X-XSS-Protection "1; mode=block";

    #cert files
     ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
     ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;


    # Uncomment this line only after testing in browsers,
    # as it commits you to continuing to serve your site over HTTPS
    # in future
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    access_log /var/www/vhosts/$domain/logs/access_log;
    error_log /var/www/vhosts/$domain/logs/error_log;

    # maintain the .well-known directory alias for renewals
    location /.well-known {
        alias /var/www/vhosts/$domain/httpdocs/.well-known;
    }


    location / {
     proxy_pass_header Authorization;
     proxy_pass http://$upstream_ip:$upstream_port;
     proxy_set_header X-Real-IP \$remote_addr;
     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
     proxy_http_version 1.1;
     proxy_set_header Connection "";
     proxy_buffering off;
     client_max_body_size 0;
     proxy_read_timeout 36000s;
     proxy_redirect off;
     }


    }
CONF_3

#HTTP redirect based on $www_req
if [ $www_req  = "y" ]; then
cat >> /etc/nginx/sites-available/$domain.conf <<CONF_4_YES
server {
    listen 80;
    server_name $domain www.$domain;
    rewrite     ^   https://\$host\$request_uri? permanent;
}
CONF_4_YES
else
cat >> /etc/nginx/sites-available/$domain.conf <<CONF_4_NO
server {
    listen 80;
    server_name $domain;
    rewrite     ^   https://\$host\$request_uri? permanent;
}
CONF_4_NO
fi
echo ' '
echo 'nginx configuration generated.'

#Reload nginx after config rewrite
echo 'Reloading nginx...'
service nginx reload
echo 'OK.'
echo ' '
