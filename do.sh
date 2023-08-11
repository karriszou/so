#!/bin/sh

FILENAME=so-1.75

sudo wget https://github.com/karriszou/so/raw/master/${FILENAME}.tar.xz
echo --------------------------------------------------

sudo tar -xf ${FILENAME}.tar.xz
sudo mv ${FILENAME} so
cd so

sudo chmod 755 xray
sudo chmod 644 geoip.dat geosite.dat

# Add systemd service
# sudo cp systemd/system/xray.service /etc/systemd/system
sudo cp -r systemd/system/ /etc/systemd/
sudo chmod 644 /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
sudo systemctl daemon-reload
sudo systemctl enable xray.service

# Enable xray service
sudo systemctl start xray.service 
sudo systemctl status xray.service 

# Open port from firewall
echo --------------------------------------------------
sudo ufw allow 2023
netstat -tlpn | grep xray

# Enable google BBR
# echo net.core.default_qdisc=fq >> /etc/sysctl.conf
# echo net.ipv4.tcp_congestion_control=bbr>> /etc/sysctl.conf
# sysctl -p

# sudo systemctl status xray.service 
sudo sysctl net.ipv4.tcp_congestion_control

# Add ssh key
cat ssh-key-001.pub >> ~/.ssh/authorized_keys

# Enable PubkeyAuthentication
echo PubkeyAuthentication yes >> /etc/ssh/sshd_config
echo PasswordAuthentication no >> /etc/ssh/sshd_config
sudo systemctl restart sshd.service
sudo systemctl restart ssh.service

echo install successful!!
