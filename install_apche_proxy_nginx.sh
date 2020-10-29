#!/bin/bash

# This scrip will install and configure NGINX as proxy server for Apache with Engintron caching and optimizations.
# For more information about the caching and NGINX optimizations see the official Engintron github https://github.com/engintron/engintron
#

# Stop Script if encontering an error.
set -e

fqdn=null
phpv=7.4

enable_nginx(){
	echo -e "\e[39mChanging Apache prots to 8080|8443"
	sed -i 's/80/8080/g' /etc/apache2/ports.conf
	sed -i 's/443/8443/g' /etc/apache2/ports.conf
	sed -i 's/80/8080/g'  /etc/apache2/sites-available/*.conf
	sed -i 's/443/8443/g'  /etc/apache2/sites-available/*.conf
	systemctl restart apache2.service
	echo "Starting NGINX"
	systemctl enable nginx.service
	systemctl start nginx.service
	echo 1 > /etc/Engintron
}

disable_nginx(){
	echo -e "\e[39mChanging Apache prots to 80|443"
	sed -i 's/8080/80/g' /etc/apache2/ports.conf
	sed -i 's/8443/443/g' /etc/apache2/ports.conf
	sed -i 's/8080/80/g'  /etc/apache2/sites-available/*.conf
	sed -i 's/8443/443/g'  /etc/apache2/sites-available/*.conf
	echo "Stopping NGINX"
	systemctl disable nginx.service
	systemctl stop nginx.service
	systemctl restart apache2.service
	echo 0 > /etc/Engintron
}

self_signed_ssl(){
   openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=NY/ST=NY/L=New Yourk/O=Yvggeniy/CN=$fqdn" -keyout /etc/ssl/private/$fqdn.key -out /etc/ssl/private/$fqdn.crt
   echo -e "\e[32mUsing SSL located at: "
   crt=/etc/ssl/private/$fqdn.crt
   key=/etc/ssl/private/$fqdn.key
   echo $crt
   echo $key
   echo -e "\e[39m"
   echo "Done"
}

install_phpfpm(){
	echo "Instaling php$phpv-fpm..."
	apt install software-properties-common -y
	add-apt-repository ppa:ondrej/php -y
	apt update
	
	# Test if the php version the user have given exists.
	### code here ###
	
	# Start PHP installation
	apt install php$phpv-fpm libapache2-mod-php$phpv php$phpv-cli php$phpv-mysql php$phpv-gd php$phpv-imagick php$phpv-tidy php$phpv-xml php$phpv-xmlrpc php$phpv-curl php$phpv-mbstring php$phpv-bcmath php$phpv-soap php$phpv-zip php$phpv-intl -y  
	# set pm settings
	echo "Configuring www.conf file..."
	sed -i "s/pm = dynamic/pm = ondemand/g" /etc/php/$phpv/fpm/pool.d/www.conf
	sed -i "s/;pm.process_idle_timeout = 10s;/pm.process_idle_timeout = 30s;/g" /etc/php/$phpv/fpm/pool.d/www.conf
	if free -m | awk '{ print $2}' | awk 'NR==2{print}' > 2000; then
		echo "Server have 2GB RAM or less, stting pm.max_children to 40 "
		sed -i "s/pm.max_children = 5/pm.max_children = 40/g" /etc/php/$phpv/fpm/pool.d/www.conf
	elif  free -m | awk '{ print $2}' | awk 'NR==2{print}' > 4000 ; then
		echo "Server have 4GB RAM or less, stting pm.max_children to 60 "
		sed -i "s/pm.max_children = 5/pm.max_children = 60/g" /etc/php/$phpv/fpm/pool.d/www.conf
	elif  free -m | awk '{ print $2}' | awk 'NR==2{print}' > 8000 ; then
		echo "Server have 8GB RAM or less, stting pm.max_children to 80 "
		sed -i "s/pm.max_children = 5/pm.max_children = 80/g" /etc/php/$phpv/fpm/pool.d/www.conf
	else
		echo "Server have more tahn 8GB of RAM, stting pm.max_children to 100"
		sed -i "s/pm.max_children = 5/pm.max_children = 100/g" /etc/php/$phpv/fpm/pool.d/www.conf
	fi

	# set php.ini settings
	echo "Configuring php.ini file..."
	var=$(grep memory_limit /etc/php/$phpv/fpm/php.ini)
	sed -i "s/$var/memory_limit = 256M/g" /etc/php/$phpv/fpm/php.ini
	
	var=$(grep post_max_size /etc/php/$phpv/fpm/php.ini)
	sed -i "s/$var/post_max_size = 16M/g" /etc/php/$phpv/fpm/php.ini
	
	var=$(grep upload_max_filesize /etc/php/$phpv/fpm/php.ini)
	sed -i "s/$var/upload_max_filesize = 64/g" /etc/php/$phpv/fpm/php.ini
	
	echo "Disabling high vulnerability php functions..."
	var=$(grep disable_functions /etc/php/$phpv/fpm/php.ini)
	sed -i "s/$var/disable_functions = ini_set,php_uname,getmyuid,getmypid,passthru,leak,listen,diskfreespace,tmpfile,link,ignore_user_abord,shell_exec,dl,set_time_limit,exec,system,highlight_file,source,show_source,fpaththru,virtual,posix_ctermid,posix_getcwd,posix_getegid,posix_geteuid,posix_getgid,posix_getgrgid,posix_getgrnam,posix_getgroups,posix_getlogin,posix_getpgid,posix_getpgrp,posix_getpid,posix,_getppid,posix_getpwnam,posix_getpwuid,posix_getrlimit,posix_getsid,posix_getuid,posix_isatty,posix_kill,posix_mkfifo,posix_setegid,posix_seteuid,posix_setgid,posix_setpgid,posix_setsid,posix_setuid,posix_times,posix_ttyname,posix_uname,proc_open,proc_close,proc_get_status,proc_nice,proc_terminate,popen,curl_exec,curl_multi_exec,parse_ini_file,allow_url_fopen,allow_url_include,pcntl_exec,chgrp,chmod,chown,lchgrp,lchown,putenv,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare/g" /etc/php/$phpv/fpm/php.ini
	
	echo "Restarting php-fpm"
	service php$phpv-fpm restart
}

install_apache(){
	echo "Instaling Apache..."
	apt update 
	apt install links2 -y
	apt install apache2 -y
	
	a2dismod php$phpv
	a2dismod mpm_prefork
	a2enmod rewrite
	a2enmod headers
	a2enmod expires
	a2enmod mpm_event
	a2enmod proxy
	a2enmod proxy_fcgi
	a2enmod ssl
	
	
	touch /etc/apache2/sites-available/$fqdn.conf
	echo "
	<VirtualHost *:80>
        # Domain name the virtual host is listening to.
		ServerName $fqdn
		ServerAlias www.$fqdn

        # Location of the website files and the index file.
		DocumentRoot /var/www/html/

        # Location of the error and access log files.
		ErrorLog /var/log/apache2/$fqdn-error.log
		CustomLog /var/log/apache2/$fqdn.log combined

        # Set all files that end in .php tu use socket.
		<FilesMatch \.php$>
		SetHandler 'proxy:unix:/run/php/php$phpv-fpm.sock|fcgi://localhost/'
		</FilesMatch>

        # Set of permissions to the website directory and to allow the use of .htaccess, will work with most websites.
		<Directory /var/www/html>
		Options FollowSymlinks
		AllowOverride All
		Order allow,deny
		Allow from all
		</Directory>

	</VirtualHost>

	<VirtualHost *:443>
        # Domain name the virtual host is listening to.
		ServerName $fqdn
		ServerAlias www.$fqdn

        # Location of the website files and the index file.
		DocumentRoot /var/www/html/

        # Location of the error and access log files.
		ErrorLog /var/log/apache2/$fqdn-error.log
		CustomLog /var/log/apache2/$fqdn.log combined

        # Set all files that end in .php tu use socket.
		<FilesMatch \.php$>
		SetHandler 'proxy:unix:/run/php/php$phpv-fpm.sock|fcgi://localhost/'
		</FilesMatch>

        # Set of permissions to the website directory and to allow the use of .htaccess, will work with most websites.
		<Directory /var/www/html>
		Options FollowSymlinks
		AllowOverride All
		Order allow,deny
		Allow from all
		</Directory>
        # Enable SSL and set the path for the PK and CRT
		SSLEngine on
		SSLCertificateFile /etc/ssl/private/$fqdn.crt
		SSLCertificateKeyFile /etc/ssl/private/$fqdn.key
		
	</VirtualHost>
"> /etc/apache2/sites-available/$fqdn.conf
	
	a2ensite $fqdn
	systemctl stop apache2.service
	# Fix Permissions to root directory
	chown -R www-data:www-data /var/www/html
	
}

install_engintron(){

# Get SSL location
if grep --quiet SSLCertificateFile /etc/apache2/sites-enabled/*.conf; then
    if grep --quiet SSLCertificateFile /etc/apache2/sites-enabled/$fqdn.conf; then
    crt=$(cat /etc/apache2/sites-enabled/$fqdn.conf | grep SSLCertificateFile | awk '{ print $2}')
    key=$(cat /etc/apache2/sites-enabled/$fqdn.conf | grep SSLCertificateKeyFile | awk '{ print $2}')
    echo -e "\e[32mUsing SSL located at: "
    echo -e $crt
    echo -e $key
    echo -e "\e[39m"

    else
    crt=$(cat /etc/apache2/sites-enabled/*.conf | grep SSLCertificateFile | awk '{ print $2}')
    key=$(cat /etc/apache2/sites-enabled/*.conf | grep SSLCertificateKeyFile | awk '{ print $2}')
    echo -e "\e[32mUsing SSL located at: "
    echo -e $crt
    echo -e $key
    echo -e "\e[39m"
    fi
    echo "Done"
	
else
   echo "Can't find Usble SSL, generatin self-signed SSL for " $fqdn
   self_signed_ssl
fi

echo -e "\e[39mPulling engintron configs from github."
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/nginx.conf -O /etc/nginx/nginx.conf
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/common_http.conf -O /etc/nginx/common_http.conf
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/common_https.conf -O /etc/nginx/common_https.conf
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/custom_rules -O /etc/nginx/custom_rules
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/proxy_params_common -O /etc/nginx/proxy_params_common
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/proxy_params_dynamic -O /etc/nginx/proxy_params_dynamic
wget https://raw.githubusercontent.com/engintron/engintron/master/nginx/proxy_params_static -O /etc/nginx/proxy_params_static
echo -e "\e[32mAll custom engintron config were downloaded.\e[39m"

echo "Cangeing nginx user to www-data"
sed -i 's/user nginx/user www-data/g' /etc/nginx/nginx.conf
sed -i '55 a set $PROXY_DOMAIN_OR_IP "127.0.0.1";' /etc/nginx/custom_rules

echo "Blocking malicious robots and web crawlers"
echo "if (\$http_user_agent ~* (360Spider|80legs.com|Abonti|AcoonBot|Acunetix|adbeat_bot|AddThis.com|adidxbot|ADmantX|AhrefsBot|AngloINFO|Antelope|Applebot|BaiduSpider|BeetleBot|billigerbot|binlar|bitlybot|BlackWidow|BLP_bbot|BoardReader|Bolt\ 0|BOT\ for\ JCE|Bot\ mailto\:craftbot@yahoo\.com|casper|CazoodleBot|CCBot|checkprivacy|ChinaClaw|chromeframe|Clerkbot|Cliqzbot|clshttp|CommonCrawler|CPython|crawler4j|Crawlera|CRAZYWEBCRAWLER|Curious|Custo|CWS_proxy|Default\ Browser\ 0|diavol|DigExt|Digincore|DIIbot|discobot|DISCo|DoCoMo|DotBot|Download\ Demon|DTS.Agent|EasouSpider|eCatch|ecxi|EirGrabber|Elmer|EmailCollector|EmailSiphon|EmailWolf|Exabot|ExaleadCloudView|ExpertSearchSpider|ExpertSearch|Express\ WebPictures|ExtractorPro|extract|EyeNetIE|Ezooms|F2S|FastSeek|feedfinder|FeedlyBot|FHscan|finbot|Flamingo_SearchEngine|FlappyBot|FlashGet|flicky|Flipboard|g00g1e|Genieo|genieo|GetRight|GetWeb\!|GigablastOpenSource|GozaikBot|Go\!Zilla|Go\-Ahead\-Got\-It|GrabNet|grab|Grafula|GrapeshotCrawler|GTB5|GT\:\:WWW|Guzzle|harvest|heritrix|HMView|HomePageBot|HTTP\:\:Lite|HTTrack|HubSpot|ia_archiver|icarus6|IDBot|id\-search|IlseBot|Image\ Stripper|Image\ Sucker|Indigonet|Indy\ Library|integromedb|InterGET|InternetSeer\.com|Internet\ Ninja|IRLbot|ISC\ Systems\ iRc\ Search\ 2\.1|JetCar|JobdiggerSpider|JOC\ Web\ Spider|Jooblebot|kanagawa|KINGSpider|kmccrew|larbin|LeechFTP|Lingewoud|LinkChecker|linkdexbot|LinksCrawler|LinksManager\.com_bot|linkwalker|LinqiaRSSBot|LivelapBot|ltx71|LubbersBot|lwp\-trivial|Mail.RU_Bot|masscan|Mass\ Downloader|maverick|Maxthon$|Mediatoolkitbot|MegaIndex|MegaIndex|megaindex|MFC_Tear_Sample|Microsoft\ URL\ Control|microsoft\.url|MIDown\ tool|miner|Missigua\ Locator|Mister\ PiX|mj12bot|MSFrontPage|msnbot|Navroad|NearSite|NetAnts|netEstate|NetSpider|NetZIP|Net\ Vampire|NextGenSearchBot|nutch|Octopus|Offline\ Explorer|Offline\ Navigator|OpenindexSpider|OpenWebSpider|OrangeBot|Owlin|PageGrabber|PagesInventory|panopta|panscient\.com|Papa\ Foto|pavuk|pcBrowser|PECL\:\:HTTP|PeoplePal|Photon|PHPCrawl|planetwork|PleaseCrawl|PNAMAIN.EXE|PodcastPartyBot|prijsbest|proximic|psbot|purebot|pycurl|QuerySeekerSpider|R6_CommentReader|R6_FeedFetcher|RealDownload|ReGet|Riddler|Rippers\ 0|RSSingBot|rv\:1.9.1|RyzeCrawler|SafeSearch|SBIder|Scrapy|Scrapy|SeaMonkey$|search.goo.ne.jp|SearchmetricsBot|search_robot|SemrushBot|Semrush|SentiBot|SEOkicks|SeznamBot|ShowyouBot|SightupBot|SISTRIX|sitecheck\.internetseer\.com|siteexplorer.info|SiteSnagger|skygrid|Slackbot|Slurp|SmartDownload|Snoopy|Sogou|Sosospider|spaumbot|Steeler|sucker|SuperBot|Superfeedr|SuperHTTP|SurdotlyBot|Surfbot|tAkeOut|Teleport\ Pro|TinEye-bot|TinEye|Toata\ dragostea\ mea\ pentru\ diavola|Toplistbot|trendictionbot|TurnitinBot|turnit|URI\:\:Fetch|urllib|Vagabondo|Vagabondo|vikspider|VoidEYE|VoilaBot|WBSearchBot|webalta|WebAuto|WebBandit|WebCollage|WebCopier|WebFetch|WebGo\ IS|WebLeacher|WebReaper|WebSauger|Website\ eXtractor|Website\ Quester|WebStripper|WebWhacker|WebZIP|Web\ Image\ Collector|Web\ Sucker|Wells\ Search\ II|WEP\ Search|WeSEE|Widow|WinInet|woobot|woopingbot|worldwebheritage.org|Wotbox|WPScan|WWWOFFLE|WWW\-Mechanize|Xaldon\ WebSpider|XoviBot|yacybot|YisouSpider|YandexBot|Yandex|zermelo|Zeus|zh-CN|ZmEu|ZumBot|ZyBorg) ) {
    return 410;
}" >> /etc/nginx/custom_rules

echo "Fixing common_http.conf"
sed -i 's/try_files $uri $uri\/ /try_files $uri /g' /etc/nginx/common_http.conf


echo "Creating default.conf files"
touch /etc/nginx/conf.d/default.conf
touch /etc/nginx/conf.d/default_https.conf
mkdir -p /var/cache/nginx


echo "
server {
    #listen 80 default_server;
    listen [::]:80 default_server ipv6only=off;
    server_name exampleip www.exampleip;
    return  301 https://\$server_name\$request_uri;
    # Set the port for HTTP proxying
    set \$PROXY_TO_PORT 8080;
    include common_http.conf;
}
" > /etc/nginx/conf.d/default.conf

echo "
# Default definition block for HTTPS
server {
    listen 443 ssl http2 default_server;
    #listen [::]:443 ssl http2 default_server;
    server_name exampleip www.exampleip;
    ssl_certificate      sslcrt;
    ssl_certificate_key  sslkey;
    include common_https.conf;
}
##### Additional Domains #####
#server {
#
#    listen 443 ssl http2;
#    server_name example.com www.example.com;
#
#    ssl_certificate      /etc/ssl/certs/exampleip;
#    ssl_certificate_key  /etc/ssl/private/exampleip;
#
#    include common_https.conf;
#}
" > /etc/nginx/conf.d/default_https.conf



echo "Set domain name"
sed -i "s/exampleip/$fqdn/g" /etc/nginx/conf.d/default.conf
sed -i "s/exampleip/$fqdn/g" /etc/nginx/conf.d/default_https.conf


echo "Set domain SSL"
# fix patch for sed command
crt=$(echo $crt | sed 's_/_\\/_g')
key=$(echo $key | sed 's_/_\\/_g')
sed -i "s/sslcrt/$crt/g" /etc/nginx/conf.d/default_https.conf
sed -i "s/sslkey/$key/g" /etc/nginx/conf.d/default_https.conf


if grep --quiet 8080 /etc/apache2/ports.conf; then
   echo -e "\e[32mPorts alredy changed\e[39m"
else
   echo -e "\e[39mChanging Apache prots to 8080|8443"
   sed -i 's/80/8080/g' /etc/apache2/ports.conf
   sed -i 's/443/8443/g' /etc/apache2/ports.conf
   sed -i 's/80/8080/g'  /etc/apache2/sites-available/*.conf
   sed -i 's/443/8443/g'  /etc/apache2/sites-available/*.conf
fi

echo "Generate dhparam for engintron"
if [ ! -d /etc/ssl/engintron ]; then
    mkdir -p /etc/ssl/engintron
fi

echo -e "\e[92mCreating dhparam SSL"
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
echo -e "\e[32mdhparam was created sucssefuly!"
echo -e "\e[39m"

echo "Restarting apache service"
systemctl restart apache2.service
systemctl enable apache2.service

echo "Restarting nginx service"
service nginx restart

if netstat -ntlp | grep "80" | grep "nginx" && netstat -ntlp | grep "443" | grep "nginx" ; then
   echo -e "\e[32mNGINX Is UP on ports 80 and 443\e[39m"
else
   echo -e "\e[41mSomting went wrong with NGINX configuration\e[39m"
fi

if netstat -ntlp | grep "80" | grep "apache" && netstat -ntlp | grep "443" | grep "apache" ; then
   echo -e "\e[32mApache Is UP on ports 8080 and 8443\e[39m"
   echo -e "\e[39mInstallation completed successfully!"
   touch /etc/Engintron
   echo 1 > /etc/Engintron
   
else
   echo -e "\e[41mSomting went wrong with Apache configuration\e[39m"
fi

}

# Test if the server meets minimum requirements

if [ -f /etc/Engintron ]; then
	if	cat /etc/Engintron == 1; then
		read -p "Disable NGINX Proxy?" -n 1 -r
		echo ""
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			disable_nginx
		fi
	elif cat /etc/Engintron == 0; then
		read -p "Enable NGINX Proxy?" -n 1 -r
		echo ""
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			enable_nginx
		fi
	fi
	
else	
		# is apache installed?
	if [ ! -d /etc/apache2 ] && [ ! -f /etc/Engintron ] ; then
		echo -e "\e[31mApache is not installed on this server."
		echo -e "You are about to install Apache with NGINX as a proxy pleas make sure you are duing it on a fresh Ubuntu 18.04 server installation.\e[39m"
		echo -e "\e[39mPlease consult with an expert before proceeding."

		read -p "Are you sure you want to install Apache and NGINX on this server? [y/n] " -n 1 -r
		echo ""
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo "Starting Installation process... "
			read -p "Please indicate PHP version (i.e: 7.4 or 7.3 and so on... ): " phpv
			if [[ "$phpv" =~ ^[5-9]\.[0-9]$ ]]; then
				echo "php$phpv Will be Installed."
				read -p "Please imput FQDN (i.e: example.com ): " fqdn
				if [[ "$fqdn" =~ [\-a-zA-Z0-9]+\.[a-zA-Z0-9]+$ ]]; then
				install_phpfpm
				self_signed_ssl
				install_apache
				apt install nginx -y
				install_engintron
				
				else
				echo -e "\e[31m The Domain: $fqdn \e[39mIs not a Domain."
				echo "Exiting.."
				fi
			else
				echo -e "\e[31m php$phpv \e[39mIs not a valid PHP version."
				echo "Exiting.."
			fi
			
		elif [[ $REPLY =~ ^[Nn]$ ]]; then
			echo "Exiting."
			exit 1
		fi

	
	else
	# Test if NGINX is allredy installed on the server
		if [ -d /etc/nginx ] ; then
			echo -e "\e[31mNGINX allrdy installed..."
			echo -e "Are you sure uknow waht you are doing?\e[39m"
			echo -e "\e[39mPlease consult with an expert before proceeding."
			exit 1
		else
			# Imput Domain name
			read -p "Please imput FQDN (i.e: example.com ): " fqdn

   
			# Stop Apache service
			echo "Stoping Apache service..."
			systemctl stop apache2.service
   
			# Install NGINX
			echo "Instaling nginx..."
			apt update
			apt install nginx -y
			systemctl enable nginx.service
			install_engintron
		fi
	fi


	
fi



# End Scrip
