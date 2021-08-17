#!/bin/bash
## [rev: c09b031]
##
## Copyright 2021 Andy Dustin
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except 
## in compliance with the License. You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software distributed under the License is 
## distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and limitations under the License.
##

## This script checks for compliance against CIS CentOS Linux 7 Benchmark v2.1.1 2017-01-31 measures
## Each individual standard has it's own function and is forked to the background, allowing for 
## multiple tests to be run in parallel, reducing execution time.

## You can obtain a copy of the CIS Benchmarks from https://www.cisecurity.org/cis-benchmarks/

### Variables ###
## This section defines global variables used in the script
printf "Enter name of File:"
read -r name
#1. Initial Setup 
nginx -v >> $name
#Configure Software Updates
yum repolist -v nginx >> $name
#Ensure the latest software package is installed (Not Scored)
yum info nginx >> $name
#Ensure only required modules are installed
nginx -V >> $name
#Ensure HTTP WebDAV module is not installed (Scored)
nginx -V 2>&1 | grep http_dav_module >> $name
#Ensure modules with gzip functionality are disabled (Scored)
nginx -V | grep 'http_gzip_module\|http_gzip_static_module' >> $name
#Ensure the autoindex module is disabled (Scored)
egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf >> $name
egrep -i '^\s*autoindex\s+' /etc/nginx/conf.d/* >> $name
#Ensure that NGINX is run using a non-privileged, dedicated service account (Not Scored)
grep "user[^;]*;" /etc/nginx/nginx.conf >> $name
grep "user[^;]*;" /etc/nginx/nginx.conf >> $name
sudo -l -U nginx >> $name
#Ensure the NGINX service account is locked (Scored)
passwd -S nginx >> $name
#Ensure the NGINX service account has an invalid shell (Scored)
grep nginx /etc/passwd >> $name
#Ensure NGINX directories and files are owned by root (Scored)
stat /etc/nginx >> $name
#Ensure access to NGINX directories and files is restricted (Scored)
find /etc/nginx -type d | xargs ls -ld >> $name
#Ensure the NGINX process ID (PID) file is secured (Scored)
ls -l /var/run/nginx.pid >> $name
#Ensure the core dump directory is secured (Not Scored)
grep working_directory /etc/nginx/nginx.conf >> $name
#Ensure NGINX only listens for network connections on authorized ports (Not Scored)
grep -ir listen /etc/nginx >> $name
#Ensure requests for unknown host names are rejected (Not Scored)
curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com' >> $name
#Ensure keepalive_timeout is 10 seconds or less, but not 0 (Scored)
grep -ir keepalive_timeout /etc/nginx >> $name
#Ensure send_timeout is set to 10 seconds or less, but not 0 (Scored)
grep -ir send_timeout /etc/nginx >> $name
#Information Disclosure
#Ensure server_tokens directive is set to `off` (Scored)
curl -I 127.0.0.1 | grep -i server >> $name
#Ensure default error and index.html pages do not reference NGINX (Scored)
grep -i nginx /usr/share/nginx/html/index.html >> $name
grep -i nginx /usr/share/nginx/html/50x.html >> $name
#Ensure hidden file serving is disabled (Not Scored)
grep location /etc/nginx/nginx.conf >> $name
#Ensure the NGINX reverse proxy does not enable information disclosure (Scored)
grep proxy_hide_header /etc/nginx/nginx.conf >> $name
#Logging 
#Ensure detailed logging is enabled (Not Scored)
cat /etc/nginx/nginx.conf >> $name
#Ensure access logging is enabled (Scored)
grep -ir access_log /etc/nginx >> $name
#Ensure error logging is enabled and set to the info logging level (Scored)
grep error_log /etc/nginx/nginx.conf >> $name
#Ensure log files are rotated (Scored)
cat /etc/logrotate.d/nginx | grep weekly >> $name
cat /etc/logrotate.d/nginx | grep rotate >> $name
#Ensure error logs are sent to a remote syslog server (Not Scored)
grep -ir syslog /etc/nginx >> $name
#Ensure proxies pass source IP information (Scored)
proxy_set_header X-Real-IP $remote_addr; >> $name
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; >> $name 
#Ensure a trusted certificate and trust chain is installed (Not Scored)
grep -ir ssl_certificate /etc/nginx/ >> $name
#Ensure only modern TLS protocols are used (Scored)
grep -ir ssl_protocol /etc/nginx >> $name
#Disable weak ciphers (Scored)
grep -ir ssl_ciphers /etc/nginx/ && grep -ir proxy_ssl_ciphers /etc/nginx >> $name
#Ensure custom Diffie-Hellman parameters are used (Scored)
grep ssl_dhparam /etc/nginx/nginx.conf >> $name
#Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Scored)
grep -ir ssl_stapling /etc/nginx >> $name
#Ensure HTTP Strict Transport Security (HSTS) is enabled (Scored)
grep -ir Strict-Transport-Security /etc/nginx >> $name
#Ensure HTTP Public Key Pinning is enabled (Not Scored)
grep -ir Public-Key-Pins /etc/nginx >> $name
#Ensure upstream server traffic is authenticated with a client certificate (Scored)
grep -ir proxy_ssl_certificate /etc/nginx >> $name
#Ensure the upstream traffic server certificate is trusted (Not Scored)
grep -ir proxy_ssl_trusted_certificate /etc/nginx >> $name
grep -ir proxy_ssl_verify /etc/nginx >> $name
#Ensure HTTP Public Key Pinning is enabled (Not Scored)
grep -ir Public-Key-Pins /etc/nginx >> $name
#Ensure upstream server traffic is authenticated with a client certificate (Scored)
grep -ir proxy_ssl_certificate /etc/nginx >> $name
#Ensure the upstream traffic server certificate is trusted (Not Scored)
grep -ir proxy_ssl_trusted_certificate /etc/nginx >> $name
grep -ir proxy_ssl_verify /etc/nginx >> $name
#Ensure session resumption is disabled to enable perfect forward security (Scored)
grep -ir ssl_session_tickets /etc/nginx >> $name
#Ensure HTTP/2.0 is used (Not Scored)
grep -ir http2 /etc/nginx >> $name
#Ensure only whitelisted HTTP methods are allowed (Not Scored)
curl -X DELETE http://localhost/index.html >> $name
curl -X GET http://localhost/index.html >> $name
#Request Limits
#Ensure timeout values for reading the client header and body are set correctly (Scored)
grep -ir timeout /etc/nginx >> $name
#Ensure the maximum request body size is set correctly (Scored)
grep -ir client_max_body_size /etc/nginx >> $name
#Ensure the maximum buffer size for URIs is defined (Scored)
grep -ir large_client_header_buffers /etc/nginx/ >> $name
#Browser Security
#Ensure X-Frame-Options header is configured and enabled (Scored)
grep -ir X-Frame-Options /etc/nginx >> $name
#Ensure X-Content-Type-Options header is configured and enabled (Scored)
grep -ir X-Content-Type-Options /etc/nginx >> $name
#Ensure the X-XSS-Protection Header is enabled and configured properly (Scored)
grep -ir X-Xss-Protection /etc/nginx >> $name
#Ensure that Content Security Policy (CSP) is enabled and configured properly (Not Scored)
grep -ir Content-Security-Policy /etc/nginx >> $name
#Ensure the Referrer Policy is enabled and configured properly (Not Scored)
grep -r Referrer-Policy /etc/nginx >> $name