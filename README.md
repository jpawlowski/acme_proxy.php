# acme_proxy.php
A PHP script to proxy [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) challenge validation requests towards multiple backend servers, based on the hosts local DNS results.

## NGINX configuration
This is an example to enable the proxy on NGINX:

	server {
	  listen  80 default_server;
	  listen  [::]:80 default_server;
	  server_name localhost;

	  location  /.well-known/acme-challenge/ {
	    root /var/www;
	    autoindex off;
	    fastcgi_split_path_info ^(.+\.php)(/.+)$;
	    include        fastcgi_params;
	    fastcgi_param  ACME_DST_PORT 80;
	    fastcgi_param  ACME_TLS false;
	    fastcgi_param  ACME_TLS_VERIFY true;
	    fastcgi_param  ACME_DOMAINS .example.com,.example.net;
	    fastcgi_intercept_errors off;
	    fastcgi_pass  unix:/var/run/php-www.socket;
	    fastcgi_param  SCRIPT_FILENAME $document_root/acme_proxy.php;
	  }
	}
