# enginyok

Automation for Apache Proxy NGINX configuration with optimization on **Ubuntu 18.04**

Part of the script relys on Engintron configurations for the NGINX installation.
https://github.com/engintron/engintron

The purpose of this script is so that I don't have to install everything manualy every, single, blody, TIME when I need a new web server.
This scrip will install and secure the apache and nginx and will work with most popular websites platforms like WordPress and Magento.


### This is a multi purpose script.
1. You can run the script on a clean Ubuntu 18.04 server to install and auto configure Apache and php-fpm with NGINX as proxy.
    - When executing the script on a clean server you will be promt to enter the domain name(FQDN) and the php version.
    
2. You can run the script on a server with Apache already installed to add NGINX as a proxy alongside the Apache server.  
    - If Apache server alredy installed you will be only promt to enter the domain name(FQDN) and NGINX will be installed and configured.

3. If you execute the script for a scond time after a successful installation you will be granted an option to **Disable/Enable** the NGINX proxy.
    - If you encontering any issues after the NGINX installation you can simply disable the NGINX by running the script a second time.
    - To reanable nginx just run the script again.


## Ho to use enginyok?
You can download and execute the script by using the following one-liner:
```
cd /; rm -f enginyok.sh; wget https://raw.githubusercontent.com/NeoLoger/enginyok/main/enginyok.sh; bash enginyok.sh
```

* This script was created to automate initial web server creation and configuration, I recomnet to experiment and test it in a dev environment before going with it to production.
* I take no responsibility if you break your production server by using my script, like everything you find on the internet make sure to read the script before blindly using it.
