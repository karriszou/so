#!/bin/sh

FILENAME=so-1.75

sudo wget https://github.com/karriszou/so/raw/master/${FILENAME}.tar.xz
echo --------------------------------------------------

sudo tar -xf ${FILENAME}.tar.xz
sudo mv ${FILENAME} so
cd so

sudo chmod +x xray

# Add systemd service
# sudo cp systemd/system/xray.service /etc/systemd/system
sudo cp -r systemd/system/ /etc/systemd/
sudo systemctl daemon-reload
sudo systemctl enable xray.service

# Add ssh key
cat ssh-key-001.pub >> ~/.ssh/authorized_keys

# Enable PasswordAuthentication
echo PubkeyAuthentication yes >> /etc/ssh/sshd_config
# echo PasswordAuthentication no >> /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable v2ray service
sudo systemctl start xray.service 
sudo systemctl status xray.service 

# Open port
sudo ufw allow 2023
netstat -tlpn | grep xray

# Enable google BBR
# echo net.core.default_qdisc=fq >> /etc/sysctl.conf
# echo net.ipv4.tcp_congestion_control=bbr>> /etc/sysctl.conf
# sysctl -p

# sudo systemctl status v2ray.service 
sudo sysctl net.ipv4.tcp_congestion_control

echo install successful!!
