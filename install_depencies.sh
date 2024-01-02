#!/bin/bash

# Instalar Python3
echo "Instalando Python3..."
sudo apt-get install -y python3

# Instalar pip3
echo "Instalando pip3..."
sudo apt-get install -y python3-pip

# Instalar Scapy
echo "Instalando Scapy..."
pip3 install scapy

# Tornar o script PortScan.py executável
echo "Tornando PortScan.py um executável..."
chmod +x PortScan.py

# Mover PortScan.py para /usr/local/bin e renomear para 'portscan'
echo "Movendo PortScan.py para /usr/local/bin e renomeando para 'portscan'"
sudo mv PortScan.py /usr/local/bin/portscan

echo "Instalação concluída. Você pode agora executar o script com o comando 'portscan'."
