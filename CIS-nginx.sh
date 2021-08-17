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
echo "1. Initial Setup" >> $name 
nginx -v >> $name
echo "2. Configure Software Updates" >> $name
yum repolist -v nginx >> $name
echo "3. Ensure the latest software package is installed (Not Scored)" >> $name
yum info nginx >> $name
echo "4. Ensure only required modules are installed" >> $name
nginx -V >> $name
echo "5. Ensure HTTP WebDAV module is not installed (Scored)" >> $name
nginx -V 2>&1 | grep http_dav_module >> $name
echo "6. Ensure modules with gzip functionality are disabled (Scored)" >> $name
nginx -V | grep 'http_gzip_module\|http_gzip_static_module' >> $name
echo "7. Ensure the autoindex module is disabled (Scored)" >> $name
egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf >> $name
egrep -i '^\s*autoindex\s+' /etc/nginx/conf.d/* >> $name
echo "8. Ensure that NGINX is run using a non-privileged, dedicated service account (Not Scored)" >> $name
grep "user[^;]*;" /etc/nginx/nginx.conf >> $name
grep "user[^;]*;" /etc/nginx/nginx.conf >> $name
sudo -l -U nginx >> $name
echo "9. Ensure the NGINX service account is locked (Scored)" >> $name
passwd -S nginx >> $name
echo " 10. Ensure the NGINX service account has an invalid shell (Scored)" >> $name
grep nginx /etc/passwd >> $name
echo "11. Ensure NGINX directories and files are owned by root (Scored)" >> $name
stat /etc/nginx >> $name
echo "12. Ensure access to NGINX directories and files is restricted (Scored)" >> $name
find /etc/nginx -type d | xargs ls -ld >> $name
echo "13. Ensure the NGINX process ID (PID) file is secured (Scored)" >> $name
ls -l /var/run/nginx.pid >> $name
echo "14. Ensure the core dump directory is secured (Not Scored)" >> $name
grep working_directory /etc/nginx/nginx.conf >> $name
echo "15. Ensure NGINX only listens for network connections on authorized ports (Not Scored)" $name
grep -ir listen /etc/nginx >> $name
echo "16. Ensure requests for unknown host names are rejected (Not Scored)" >> $name
curl -k -v https://127.0.0.1 -H 'Host: invalid.host.com' >> $name
echo "17. Ensure keepalive_timeout is 10 seconds or less, but not 0 (Scored)" >> $name
grep -ir keepalive_timeout /etc/nginx >> $name
echo "18. Ensure send_timeout is set to 10 seconds or less, but not 0 (Scored)" >> $name
grep -ir send_timeout /etc/nginx >> $name
echo "19. Information Disclosure" >> $name
echo "20. Ensure server_tokens directive is set to `off` (Scored)" >> $name
curl -I 127.0.0.1 | grep -i server >> $name
echo "21. Ensure default error and index.html pages do not reference NGINX (Scored)" >> $name
grep -i nginx /usr/share/nginx/html/index.html >> $name
grep -i nginx /usr/share/nginx/html/50x.html >> $name
echo "22. Ensure hidden file serving is disabled (Not Scored)" >> $name
grep location /etc/nginx/nginx.conf >> $name
echo "23. Ensure the NGINX reverse proxy does not enable information disclosure (Scored)" >> $name
grep proxy_hide_header /etc/nginx/nginx.conf >> $name
echo "24. Logging" >> $name 
echo "25. Ensure access logging is enabled (Scored)" >> $name
grep -ir access_log /etc/nginx >> $name
echo "26. Ensure error logging is enabled and set to the info logging level (Scored)" >> $name
grep error_log /etc/nginx/nginx.conf >> $name
echo "27. Ensure log files are rotated (Scored)" >> $name
cat /etc/logrotate.d/nginx | grep weekly >> $name
cat /etc/logrotate.d/nginx | grep rotate >> $name
echo "28. Ensure error logs are sent to a remote syslog server (Not Scored)" >> $name
grep -ir syslog /etc/nginx >> $name
echo "29. Ensure proxies pass source IP information (Scored)" >> $name
proxy_set_header X-Real-IP $remote_addr; >> $name
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; >> $name 
echo "30. Ensure a trusted certificate and trust chain is installed (Not Scored)" >> $name
grep -ir ssl_certificate /etc/nginx/ >> $name
echo "31. Ensure only modern TLS protocols are used (Scored)" >> $name
grep -ir ssl_protocol /etc/nginx >> $name
echo "32. Disable weak ciphers (Scored)" >> $name
grep -ir ssl_ciphers /etc/nginx/ && grep -ir proxy_ssl_ciphers /etc/nginx >> $name
echo "33. Ensure custom Diffie-Hellman parameters are used (Scored)" >> $name
grep ssl_dhparam /etc/nginx/nginx.conf >> $name
echo "34. Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Scored)" >> $name
grep -ir ssl_stapling /etc/nginx >> $name
echo "35. Ensure HTTP Strict Transport Security (HSTS) is enabled (Scored)" >> $name
grep -ir Strict-Transport-Security /etc/nginx >> $name
echo "36. Ensure HTTP Public Key Pinning is enabled (Not Scored)" >> $name
grep -ir Public-Key-Pins /etc/nginx >> $name
echo "37. Ensure upstream server traffic is authenticated with a client certificate (Scored)" >> $name
grep -ir proxy_ssl_certificate /etc/nginx >> $name
echo "38. Ensure the upstream traffic server certificate is trusted (Not Scored)" >> $name
grep -ir proxy_ssl_trusted_certificate /etc/nginx >> $name
grep -ir proxy_ssl_verify /etc/nginx >> $name
echo "39. Ensure HTTP Public Key Pinning is enabled (Not Scored)" >> $name
grep -ir Public-Key-Pins /etc/nginx >> $name
echo "40. Ensure upstream server traffic is authenticated with a client certificate (Scored)" >> $name
grep -ir proxy_ssl_certificate /etc/nginx >> $name
echo "41. Ensure the upstream traffic server certificate is trusted (Not Scored)" >> $name
grep -ir proxy_ssl_trusted_certificate /etc/nginx >> $name
grep -ir proxy_ssl_verify /etc/nginx >> $name
echo "42. Ensure session resumption is disabled to enable perfect forward security (Scored)" >> $name
grep -ir ssl_session_tickets /etc/nginx >> $name
echo "43. Ensure HTTP/2.0 is used (Not Scored)"
grep -ir http2 /etc/nginx >> $name
echo "44. Ensure only whitelisted HTTP methods are allowed (Not Scored)"
curl -X DELETE http://localhost/index.html >> $name
curl -X GET http://localhost/index.html >> $name
echo "45. Request Limits" >> $name
echo "46. Ensure timeout values for reading the client header and body are set correctly (Scored)" >> $name
grep -ir timeout /etc/nginx >> $name
echo "47. Ensure the maximum request body size is set correctly (Scored)" >> $name
grep -ir client_max_body_size /etc/nginx >> $name
echo "48. Ensure the maximum buffer size for URIs is defined (Scored)" >> $name
grep -ir large_client_header_buffers /etc/nginx/ >> $name
echo "49. Browser Security" >> $name
echo "50. Ensure X-Frame-Options header is configured and enabled (Scored)" >> $name
grep -ir X-Frame-Options /etc/nginx >> $name
echo "51. Ensure X-Content-Type-Options header is configured and enabled (Scored)" >> $name
grep -ir X-Content-Type-Options /etc/nginx >> $name
echo "52. Ensure the X-XSS-Protection Header is enabled and configured properly (Scored)" >> $name
grep -ir X-Xss-Protection /etc/nginx >> $name
echo "53. Ensure that Content Security Policy (CSP) is enabled and configured properly (Not Scored)" >> $name
grep -ir Content-Security-Policy /etc/nginx >> $name
echo "54. Ensure the Referrer Policy is enabled and configured properly (Not Scored)" >> $name
grep -r Referrer-Policy /etc/nginx >> $name
