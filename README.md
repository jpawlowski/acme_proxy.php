# acme_proxy.php
A PHP script to proxy ACME challenge validation requests towards a backend server

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
	    fastcgi_param  QUERY_STRING $query_string;
	    fastcgi_intercept_errors off;
	    fastcgi_pass  unix:/var/run/php-www.socket;
	    fastcgi_param  SCRIPT_FILENAME $document_root/acme_proxy.php;
	  }
	}
