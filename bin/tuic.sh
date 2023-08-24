#!bin/bash

# filepath='https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-musl'
filepaht='https://github.com/karriszou/so/raw/master/bin/tuic-server-1.0.0-musl'

red='\033[0;31m'
yellow='\033[0;33m'
bblue='\033[0;34m'
plain='\033[0m'

blue( ) { echo -e "\033[36m\033[01m$1\033[0m";}
red( ) { echo -e "\033[31m\033[01m$1\033[0m";}
green( ) { echo -e "\033[32m\033[01m$1\033[0m";}
yellow( ) { echo -e "\033[33m\033[01m$1\033[0m";}
white( ) { echo -e "\033[37m\033[01m$1\033[0m";}
readp( ) { read -p "$(yellow "$1")" $2;}

[[ $EUID -ne 0 ]] && yellow "please run with root!" && exit
#[[ -e /etc/hosts ]] && grep -qE '^ *172.65.251.78 gitlab.com' /etc/hosts || echo -e '\n172.65.251.78 gitlab.com' >> /etc/hosts
yellow "Scanning VPS info......"
if [[ -f /etc/redhat-release ]]; then
    release="Centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
    release="Debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="Ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="Centos"
elif cat /proc/version | grep -q -E -i "debian"; then
    release="Debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="Ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="Centos"
else 
    red "Your system is unsupported! Please use Ubuntu,Debian,Centos system." && exit
fi

vsid=`grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1`

sys( ) {
    [ -f /etc/os-release ] && grep -i pretty_name /etc/os-release | cut -d \" -f2 && return
    [ -f /etc/lsb-release ] && grep -i description /etc/lsb-release | cut -d \" -f2 && return
    [ -f /etc/redhat-release ] && awk '{print $0}' /etc/redhat-release && return;
}

op=`sys`
version=`uname -r | awk -F "-" '{print $1}'`
main=`uname  -r | awk -F . '{print $1}'`
minor=`uname -r | awk -F . '{print $2}'`
bit=`uname -m`
if [[ $bit = x86_64 ]]; then
    cpu=amd64
elif [[ $bit = aarch64 ]]; then
    cpu=arm64
elif [[ $bit = s390x ]]; then
    cpu=s390x
else
    red "VPS CPU architecture: $bit is unsupported, please use amd64 or arm64 architecture CPU!" && exit
fi
vi=`systemd-detect-virt`

tuic_log( ) {
echo
journalctl -u tuic --output cat -f
}

tuic_share( ) {
    if [[ -z $(systemctl status tuic 2>/dev/null | grep -w active) && ! -f '/root/tuic/tuic.json' ]]; then
    red "not installed tuic!" && exit
    fi
    red "======================================================================================"
    blue "tuic server config, saved to /root/tuic/tuic.json"
    yellow "$(cat /root/tuic/tuic.json)\n" 
    blue "v2rayn client config, saved to /root/tuic/v2rayn.json"
    yellow "$(cat /root/tuic/v2rayn.json)" && sleep 2
}

tuic_restart( ) {
    systemctl restart tuic
    if [[ -n $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/root/tuic/tuic.json' ]]; then
    green "tuic start successful!" && tuicshare
    else
    red "tuic start failed!" && exit
    fi
}

install_service( ) {
cat << EOF >/etc/systemd/system/tuic.service
[Unit]
Description=TUIC-v5
Documentation=
After=network.target
[Service]
User=root
ExecStart=/root/tuic/tuic -c /root/tuic/tuic.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tuic
systemctl start tuic
}

tuic_status( ) {
    if [[ -n $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/root/tuic/tuic.json' ]]; then
        status=$(white "tuic status: \c";green "running")
    elif [[ -z $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/root/tuic/tuic.json' ]]; then
        status=$(white "tuic status: \c";yellow "inactive")
    else
        status=$(white "tuic status: \c";red "not install")
    fi
}

tuic_uninstall( ) {
    systemctl stop tuic >/dev/null 2>&1
    systemctl disable tuic >/dev/null 2>&1
    rm -f /etc/systemd/system/tuic.service
    rm -rf /root/tuic /usr/bin/tu
    green "tuic removed!"
}

package_update( ) {
    if [[ $release = Centos ]]; then
    if [[ ${vsid} =~ 8 ]]; then
        yum clean all && yum makecache
    fi
        yum install epel-release -y
    else
        apt update
    fi
}

install_core( ) {
    if [[ -f '/root/tuic/tuic' ]]; then
        chmod +x /root/tuic/tuic
        blue "Installed TUIC core: $(/root/tuic/tuic -v)\n"
    else
        mkdir /root/tuic
        wget -NO /root/tuic/tuic ${pathfile}
        if [[ -f '/root/tuic/tuic' ]]; then
            # chmod +x /root/tuic/tuic
            chmod 755 /root/tuic/tuic
            blue "Installed TUIC core: $(/root/tuic/tuic -v)\n"
        else
            red "Install TUIC core failed!" && exit
        fi
    fi
}

v4v6( ) {
    v4=$(curl -s4m6 ip.sb -k)
    v6=$(curl -s6m6 ip.sb -k)
}

acme_package_update( ) {
    [[ $(type -P yum) ]] && yumapt='yum -y' || yumapt='apt -y'
    if [[ ! $(type -P curl) ]]; then
    $yumapt update;$yumapt install curl
    fi
    if [[ ! $(type -P lsof) ]]; then
    $yumapt update;$yumapt install lsof
    fi
    #if [[ ! $(type -P socat) ]]; then
    $yumapt update;$yumapt install socat
    #fi
    if [[ ! $(type -P yum) ]]; then
    if [[ ! $(type -P cron) ]]; then
    $yumapt update;$yumapt install cron
    fi
    else
    $yumapt update;$yumapt install cronie
    fi

    v4v6

    if [[ -z $v4 ]]; then
    yellow "Detected VPS is pure IPV6 Only, add dns64"
    echo -e "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1" > /etc/resolv.conf
    sleep 2
    fi
}

acme_open_port( ) {
    # yellow "Close the firewall and open all port rules"
    # systemctl stop firewalld.service >/dev/null 2>&1
    # systemctl disable firewalld.service >/dev/null 2>&1
    # setenforce 0 >/dev/null 2>&1
    # ufw disable >/dev/null 2>&1
    # iptables -P INPUT ACCEPT >/dev/null 2>&1
    # iptables -P FORWARD ACCEPT >/dev/null 2>&1
    # iptables -P OUTPUT ACCEPT >/dev/null 2>&1
    # iptables -t mangle -F >/dev/null 2>&1
    # iptables -F >/dev/null 2>&1
    # iptables -X >/dev/null 2>&1
    # netfilter-persistent save >/dev/null 2>&1
    if [[ -n $(apachectl -v 2>/dev/null) ]]; then
        systemctl stop httpd.service >/dev/null 2>&1
        systemctl disable httpd.service >/dev/null 2>&1
        service apache2 stop >/dev/null 2>&1
        systemctl disable apache2 >/dev/null 2>&1
    fi
    # green "all port is opened!"
    sleep 2
    if [[ -n $(lsof -i :80|grep -v "PID") ]]; then
        yellow "The port 80 is occupied, release the port 80..."
        sleep 2
        lsof -i :80|grep -v "PID"|awk '{print "kill -9",$2}'|sh >/dev/null 2>&1
        green "80 port is released!"
        sleep 2
    fi
    ufw allow 80
}

acme_register( ) {
    ca_server='letsencrypt'
    # readp "Please choose the CA server for registration (Enter to letsencrypt):" ca_server
    readp "Please enter the email address for registration (Enter to generate a virtual gmail):" Aemail
    if [ -z $Aemail ]; then
        auto=`date +%s%N |md5sum | cut -c 1-6`
        Aemail=$auto@gmail.com
    fi
    yellow "Currently registered email address: $Aemail"
    green "Installing acme.sh application certificate script"
    # wget -N https://github.com/Neilpang/acme.sh/archive/master.tar.gz >/dev/null 2>&1
    # tar -zxvf master.tar.gz >/dev/null 2>&1
    # cd acme.sh-master >/dev/null 2>&1
    # ./acme.sh --install >/dev/null 2>&1
    # cd
    curl https://get.acme.sh | sh -s email=$Aemail
    [[ -n $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && green "Install acme.sh certificate application program successfully" || red "Failed to install acme.sh certificate application program" 
    # bash ~/.acme.sh/acme.sh --set-default-ca --server ${ca_server}
    bash ~/.acme.sh/acme.sh --upgrade --use-wget --auto-upgrade
}

acme_check_tls( ) {
    fail( ) {
        red "Sorry, domain name certificate application failed"
        yellow "Suggestion 1: Change the name of the second-level domain and try again (important)"
        echo
        yellow "Suggestion 2: Change the current local network IP environment, and then try to execute the script" && exit
    }
    if [[ -f /root/cert/cert.crt && -f /root/cert/private.key ]] && [[ -s /root/cert/cert.crt && -s /root/cert/private.key ]]; then
        sed -i '/--cron/d' /etc/crontab
        echo "0 0 * * * root bash ~/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
        green "The domain name certificate application is successful or already exists!"
        green "The domain name certificate (cert.crt) and key (private.key) have been saved in the /root/cert folder" 
        yellow "$ym"
        yellow "/root/cert/cert.crt"
        yellow "/root/cert/private.key"
        echo $ym > /root/cert/ca.log
        if [[ -f '/usr/local/bin/hysteria' ]]; then
            blue "hysteria proxy protocol detected, this certificate will be applied automatically"
        fi
        if [[ -f '/usr/bin/caddy' ]]; then
            blue "naiveproxy protocol detected, this certificate will be applied automatically"
        fi
        if [[ -f '/root/tuic/tuic' ]]; then
            blue "tuic protocol detected, this certificate will be applied automatically"
        fi
        if [[ -f '/usr/bin/x-ui' ]]; then
            blue "x-ui protocol detected, This certificate can be manually filled on the panel of x-ui"
        fi
    else
        fail
    fi
}

acme_install_ca( ) {
    # bash ~/.acme.sh/acme.sh --install-cert -d ${ym} --key-file /root/cert/private.key --fullchain-file /root/cert/cert.crt --ecc
    bash ~/.acme.sh/acme.sh --install-cert -d ${ym} --ecc --key-file /root/cert/private.key --fullchain-file /root/cert/cert.crt
}

acme_check_ca( ) {
    nowca=`bash ~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}'`
    if [[ $nowca == $ym ]]; then
    red "The entered domain name has a certificate application record, so there is no need to apply again"
    red "The certificate application record is as follows:"
    bash ~/.acme.sh/acme.sh --list
    yellow "If you must reapply, please execute the delete certificate option first" && exit
    fi
}

wro( ) {
    v4v6
    if [[ -n $(echo $domain_ip | grep nginx) ]]; then
        yellow "The IP that the current domain resolves to: None"
        red "The domain resolution is invalid. Please check whether the domain is correct or wait a few minutes for the resolution to complete before executing the script" && exit 
    elif [[ -n $(echo $domain_ip | grep ":") || -n $(echo $domain_ip | grep ".") ]]; then
        if [[ $domain_ip != $v4 ]] && [[ $domain_ip != $v6 ]]; then
            yellow "The IP that the current domain resolves to: $domain_ip"
            red "The IP of the current domain resolved does not match the IP used by the current VPS"
            green "Suggestions:"
            yellow "1, Please ensure that the CDN proxy is closed (DNS only), and other domain analysis websites are set in the same way"
            yellow "2, Please check whether the IP address set by the domain resolution platform is correct"
            exit 
        else
            green "Congratulations, the domain resolve correctly, the IP that the current domain resolves to: $domain_ip"
        fi
    fi
}

ACME_issue_standalone_cert( ) {
    readp "Please enter the resolved domain:" ym
    green "Inputed domain:$ym" && sleep 1
    acme_check_ca
    domain_ip=$(curl -s ipget.net/?ip="$ym")
    wro
    if [[ $domain_ip = $v4 ]]; then
        bash ~/.acme.sh/acme.sh  --issue -d ${ym} --standalone -k ec-256 --server ${ca_server} --insecure
    fi
    if [[ $domain_ip = $v6 ]]; then
        bash ~/.acme.sh/acme.sh  --issue -d ${ym} --standalone -k ec-256 --server ${ca_server} --listen-v6 --insecure
    fi
    acme_install_ca
    acme_check_tls
}

ACME_issue_standalone_cert_check( ) {
    wgcfv6=$(curl -s6m6 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv4=$(curl -s4m6 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ ! $wgcfv4 =~ on|plus && ! $wgcfv6 =~ on|plus ]]; then
        ACME_issue_standalone_cert
    else
        systemctl stop wg-quick@wgcf >/dev/null 2>&1
        kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
        ACME_issue_standalone_cert
        systemctl start wg-quick@wgcf >/dev/null 2>&1
        systemctl restart warp-go >/dev/null 2>&1
        systemctl enable warp-go >/dev/null 2>&1
        systemctl start warp-go >/dev/null 2>&1
    fi
}

ACME_issue_DNS_api_cert( ) {
    green "Note: Before applying for a generic domain name, it is necessary to add a * record to DNS resolve(input format: *.first-level domain)"
    readp "Please enter the resolved domain:" ym
    green "Inputed domain:$ym" && sleep 1
    acme_check_ca
    freenom=`echo $ym | awk -F '.' '{print $NF}'`
    if [[ $freenom =~ tk|ga|gq|ml|cf ]]; then
        red "You are using freenom free domain, which does not support the current DNS API mode, exit." && exit 
    fi
    domain_ip=$(curl -sm5 ipget.net/?ip=$ym)
    [[ -z $domain_ip ]] && red "The certificate request is currently unavailable, please try again later" && exit
    if [[ -n $(echo $domain_ip | grep nginx) && -n $(echo $ym | grep \*) ]]; then
        green "it is currently a wildcard domain certificate application, " && sleep 2
        abc=cert.acme$(echo $ym | tr -d '*')
        domain_ip=$(curl -s ipget.net/?ip=$abc)
    else
        green "it is currently a single domain certificate application, " && sleep 2
    fi
    wro
    echo
    ab="Please select a hosted domain name resolution service provider:\n1.Cloudflare\n2.TencentCloud DNSPod\n3.Aliyun\n Please choose："
    readp "$ab" cd
    case "$cd" in 
    1 )
        readp "Please input Cloudflare Global API Key：" GAK
        export CF_Key="$GAK"
        readp "Please input Cloudflare register email address：" CFemail
        export CF_Email="$CFemail"
        if [[ $domain_ip = $v4 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${ym} -k ec-256 --server ${ca_server} --insecure
        fi
        if [[ $domain_ip = $v6 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${ym} -k ec-256 --server ${ca_server} --listen-v6 --insecure
        fi
    ;;
    2 )
        readp "Please input TencentCloud DNSPod DP_Id：" DPID
        export DP_Id="$DPID"
        readp "Please input TencentCloud DNSPod DP_Key：" DPKEY
        export DP_Key="$DPKEY"
        if [[ $domain_ip = $v4 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_dp -d ${ym} -k ec-256 --server ${ca_server} --insecure
        fi
        if [[ $domain_ip = $v6 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_dp -d ${ym} -k ec-256 --server ${ca_server} --listen-v6 --insecure
        fi
    ;;
    3 )
        readp "Please input Aliyun Ali_Key：" ALKEY
        export Ali_Key="$ALKEY"
        readp "Please input Aliyun Ali_Secret：" ALSER
        export Ali_Secret="$ALSER"
        if [[ $domain_ip = $v4 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_ali -d ${ym} -k ec-256 --server ${ca_server} --insecure
        fi
        if [[ $domain_ip = $v6 ]]; then
            bash ~/.acme.sh/acme.sh --issue --dns dns_ali -d ${ym} -k ec-256 --server ${ca_server} --listen-v6 --insecure
        fi
    esac
    acme_install_ca
    acme_check_tls
}

ACME_issue_DNS_api_cert_check( ) {
    wgcfv6=$(curl -s6m6 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv4=$(curl -s4m6 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ ! $wgcfv4 =~ on|plus && ! $wgcfv6 =~ on|plus ]]; then
        ACME_issue_DNS_api_cert
    else
        systemctl stop wg-quick@wgcf >/dev/null 2>&1
        kill -15 $(pgrep warp-go) >/dev/null 2>&1 && sleep 2
        ACME_issue_DNS_api_cert
        systemctl start wg-quick@wgcf >/dev/null 2>&1
        systemctl restart warp-go >/dev/null 2>&1
        systemctl enable warp-go >/dev/null 2>&1
        systemctl start warp-go >/dev/null 2>&1
    fi
}

acme_install( ) {
    mkdir -p /root/cert
    ab="1.Select the independent port 80 mode to apply for a certificate (only the domain is required), and port 80 will be forcibly released during the installation process\n2.Select DNS API mode to apply for a certificate (requires domain, ID, Key), and automatically identify single domain name and wildcard domain name\n0. Return to the previous level\n Please select:"
    readp "$ab" cd
    case "$cd" in 
    1 ) acme_package_update && acme_open_port && acme_register && ACME_issue_standalone_cert_check;;
    2 ) acme_package_update && acme_register && ACME_issue_DNS_api_cert_check;;
    0 ) acme;;
    esac

    ym=$(cat /root/cert/ca.log)
    if [[ ! -f /root/cert/cert.crt && ! -f /root/cert/private.key ]] && [[ ! -s /root/cert/cert.crt && ! -s /root/cert/private.key ]]; then
        red "request certificate failed, exit!" && exit
    fi
}

acme_uninstall( ) {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "acme.sh not been installed!" && exit 
    curl https://get.acme.sh | sh
    bash ~/.acme.sh/acme.sh --uninstall
    rm -rf /root/cert
    rm -rf ~/.acme.sh acme.sh
    sed -i '/--cron/d' /etc/crontab
    [[ -z $(/root/.acme.sh/acme.sh -v 2>/dev/null) ]] && green "acme.sh uninstalled successful!" || red "acme.sh uninstall failed!"
}

acme_renew( ) {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "The acme.sh is not installed and cannot be executed" && exit 
    green "The domain name shown below is successfully applied certificate:"
    bash ~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}'
    echo
    green "begin renew certificate..." && sleep 3
    bash ~/.acme.sh/acme.sh --cron -f
    acme_check_tls
}

acme_show_certificate( ) {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "The acme.sh is not installed and cannot be executed" && exit 
    green "The domain name shown below is successfully applied certificate:"
    bash ~/.acme.sh/acme.sh --list
}

acme( ) {
    acme_show( ) {
        if [[ -n $(~/.acme.sh/acme.sh -v 2>/dev/null) ]]; then
            caacme1=`bash ~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}'`
            if [[ -n $caacme1 ]]; then
                caacme=$caacme1
            else
                caacme='no certificate record'
            fi
        else
            caacme='uninstall acme'
        fi
    }

    green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"      
    yellow " Note:"
    yellow " i:     The independent port 80 mode only supports single domain certificate application, and supports automatic renewal when port 80 is not occupied"
    yellow " ii:    DNS API mode does not support freenom free domain application, supports single domain and wildcard domain certificate application, unconditional automatic renewal"
    yellow " iii:   Before applying for a wildcard domain, it is necessary to add a * record to the DNS resolve"
    green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"      
    yellow " public  crt save path:/root/cert/cert.crt"
    yellow " private key save path:/root/cert/private.key"
    echo
    red "========================================================================="
    acme_show
    blue "Currently successfully applied for certificates (domain names):"
    yellow "$caacme"
    echo
    red "========================================================================="
    green " 1. acme.sh applies for letsencrypt ECC certificate (supports independent mode and DNS API mode)"
    green " 2. Query successfully applied domain names and automatic renewal time"
    green " 3. Manual one-click certificate renewal"
    green " 9. Delete the certificate and uninstall the ACME application script"
    green " 0. exit "
    read -p "Please input number:" NumberInput
    case "$NumberInput" in     
    1 ) acme_install;;
    2 ) acme_show_certificate;;
    3 ) acme_renew;;
    9 ) acme_uninstall;;
    * ) exit      
    esac

    # if [[ ! -f /root/.acme.sh/acme.sh ]]; then
    #     # wget -N https://gitlab.com/rwkgyg/acme-script/raw/main/acme.sh && bash acme.sh
    #     wget -N https://get.acme.sh | sh; apt install socat -y || yum install socat -y;
    # fi
    # /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
}

install_certificate( ) {
    green "tuic protocol certificate request methods:"
    readp "1. acme(default)\n2. custom certificate path\nplease choose:" certificate
    if [ -z "${certificate}" ] || [ $certificate == "1" ]; then
        # touch /root/tuic/cert.crt
        # touch /root/tuic/private.key
        # cert='/root/tuic/cert.crt'
        # key='/root/tuic/private.key'

        if [[ -f /root/cert/cert.crt && -f /root/cert/private.key ]] && [[ -s /root/cert/cert.crt && -s /root/cert/private.key ]]; then
            blue "There has been a certificate in /root/cert/ !"
            readp "1. Use the certificate in /root/cert (Enter)\n2. Delete the certificate in cert and request certificate\nPlease choose:" certacme
            if [ -z "${certacme}" ] || [ $certacme == "1" ]; then       #use the exist certificate
                ym=$(cat /root/cert/ca.log)
                blue "Detect domain:$ym, and use it!\n"
            elif [ $certacme == "2" ]; then                             #re-request certificate
                acme_uninstall
                sleep 2
                acme
            fi
        else                                                            #request new certificate
            acme
        fi
        cert='/root/cert/cert.crt'
        key='/root/cert/private.key'
    elif [ $certificate == "2" ]; then
        readp "Please input public certificate file (.crt) path(/a/b/.../cert.crt):" cerroad
        blue "public certificate path:$cerroad "
        readp "Please input private key file (.key) path(/a/b/.../private.key):" keyroad
        blue "private key path:$keyroad "
        cert=$cerroad
        key=$keyroad
        readp "Please input domain:" ym
        blue "domain:$ym "
    else 
        red "input wrong, please choose" && inscertificate
    fi
}

install_port( ) {
    readp "\nset tuic port[1-65535](Enter with randowm port between 2000-65535):" port
    if [[ -z $port ]]; then
    port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]
    do
    [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]] && yellow "\nport is using, please input new port" && readp "custom tuic port:" port
    done
    else
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]
    do
    [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]] && yellow "\nport is using, please input new port" && readp "custom tuic port:" port
    done
    fi
    blue "confirm port:$port\n"
}

install_uuid( ) {
    readp "set tuic uuid(Enter with random): " uuid
    if [[ -z ${uuid} ]]; then
        uuid='51ae8941-4a31-4088-85e2-b4cff5dc5a89'
    else
        uuid='51ae8941-4a31-4088-85e2-b4cff5dc5a89'
    fi
    uuid='51ae8941-4a31-4088-85e2-b4cff5dc5a89'
    password='51ae8941-4a31-4088-85e2-b4cff5dc5a89'
    blue "confirm uuid and password: ${uuid}:${password}\n"
}

install_config( ) {
green "set tuic config file, service process...\n"
    sure_ip_adress( ) {
        ip=$(curl -s4m6 ip.sb -k) || ip=$(curl -s6m6 ip.sb -k)
    }

sure_ip_adress
cat <<EOF > /root/tuic/tuic.json
{
    "server": "[::]:$port",
    "users": {
        "$uuid": "$password"
    },
    "certificate": "$cert",
    "private_key": "$key",
    "congestion_control": "bbr",
    "alpn": ["h3", "spdy/3.1"],
    "log_level": "warn"
}
EOF

cat <<EOF > /root/tuic/v2rayn.json
{
    "relay": {
        "server": "$ym:$port",
        "uuid": "$uuid",
        "password": "$password",
        "ip": "$ip",
        "congestion_controll": "bbr",
        "alpn": ["h3", "spdy/3.1"]
    },
    "local": {
        "server": "127.0.0.1:55555"
    },
    "log_level": "warn"
}
EOF

install_service
}

tuic_install( ) {
    if [[ -n $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/root/tuic/tuic.json' ]]; then
        green "tuic has been installed!" && exit
    fi
    rm -f /etc/systemd/system/tuic.service
    # rm -rf /usr/local/bin/tuic /etc/tuic /root/tuic /usr/bin/tu

    package_update
    install_core
    install_certificate
    install_port
    install_uuid
    install_config

    if [[ -n $(systemctl status tuic 2>/dev/null | grep -w active) && -f '/root/tuic/tuic.json' ]]; then
        green "tuic service enable successful!"
        ufw allow $port
        chmod +x /root/tuic.sh 
        ln -sf /root/tuic.sh /usr/bin/tu
        if [[ ! $vi =~ lxc|openvz ]]; then
            sysctl -w net.core.rmem_max=8000000
            sysctl -p
        fi
    else
        red "tuic enable failed! please run systemctl status tuic to check, exit!" && exit
    fi

    red "======================================================================================"
    url="tuic://$ym:$port?uuid=$uuid&alpn=h3&mode=bbr#tuic-custom"
    echo ${url} > /root/tuic/URL.txt
    green "\ntuic proxy service installed, script shortcut is tu" && sleep 2
    tuic_share
}

start( ) {
    cd /root
    # ufw allow 9874
    chmod +x /root/tuic.sh
    ln -sf /root/tuic.sh /usr/bin/tu
}

start_menu( ) {
    tuic_status
    clear
    red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  
    green "  1. install tuic" 
    green "  2. display tuic config and V2rayN config"
    green "  3. view tuic log"
    green "  4. ACME"
    green "  9. uninstall tuic"
    green "  0. exit script"
    red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  
    white "VPS infomation:"
    white "OS: $(blue "$op")" && white "kernel version: $(blue "$version")" && white "CPU architecture: $(blue "$cpu")" && white "virtual type: $(blue "$vi")"
    white "$status"
    echo
    readp "Input number:" Input
    case "$Input" in     
        1 ) tuic_install;;
        2 ) tuic_share;;
        3 ) tuic_log;;
        4 ) acme;;
        9 ) tuic_uninstall;;
        * ) exit 
    esac
}

if [ $# == 0 ]; then
    start
# lastvsion=v`curl -s https://data.jsdelivr.com/v1/package/gh/EAimTY/tuic | sed -n 4p | tr -d ',"' | awk '{print $1}'`
# ygvsion=v`/root/tuic/tuic -v 2>/dev/null`
    start_menu
fi
