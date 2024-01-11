#!/usr/bin/env python3

import socket
import logging
from scapy.all import *
import time
import argparse

# Configura o Scapy para não exibir avisos
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def print_banner():
    """Imprime o banner ASCII no início da execução."""
    banner = r"""
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄ 
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌     ▐░▌
▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌▐░▌    ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░▌          ▐░█▄▄▄▄▄▄▄█░▌▐░▌ ▐░▌   ▐░▌
▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌▐░▌          ▐░█▀▀▀▀▀▀▀█░▌▐░▌   ▐░▌ ▐░▌
          ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌    ▐░▌▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░▌     ▐░▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌      ▐░░▌
 ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀        ▀▀ 
    """
    print(banner)

def get_service_version(ip, port):
    """Tenta obter a versão do serviço na porta especificada."""
    version_info = 'Desconhecido'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2) 
            s.connect((ip, port)) # Tenta estabelecer uma conexão com a porta especificada e envia um comando
            s.sendall(b"VERSION\r\n") # VERSION para tentar obter a versão do serviço rodando naquela porta
            response = s.recv(1024).decode()
            version_info = response.strip() if response else version_info
    except socket.error as e:
        version_info = f"Erro de socket: {e}"
    except Exception as e:
        version_info = f"Erro geral: {e}"
    return version_info

def scan_port_scapy(ip, port, timeout=2, retries=1, version_check=False):
    """Escaneia uma única porta usando Scapy e retorna o status, RTT e versão do serviço."""
    for _ in range(retries):
        try:
            packet = IP(dst=ip) / TCP(dport=port, flags='S') #Cria um pacote TCP/IP com a flag SYN
            start_time = time.time()
            response = sr1(packet, timeout=timeout, verbose=0) #Espera a resposta utilizando a função sr1 da Scapy
            rtt = time.time() - start_time

            if response and response.haslayer(TCP): #Verifica se a resposta existe e se é um pacote TCP
                if response.getlayer(TCP).flags == 0x12: #Verifica a flag nesse caso 0x12 é a SYN
                    version = get_service_version(ip, port) if version_check else 'Versão não verificada'
                    return 'Aberto', True, rtt, version
                elif response.getlayer(TCP).flags == 0x14: #Verifica a flag nesse caso 0x12 é a SYN-ACK
                    return 'Fechado', False, rtt, None
        except Exception as e: #Se não tiver nem um das flags anterior como reposta considera filtrada
            logging.error(f"Erro ao escanear a porta {port}: {e}") 
    return 'Filtrado', True, None, None

def get_service_name(port, check_service):
    """Obtém o nome do serviço para a porta especificada, se possível."""
    if check_service:
        try:
            service = socket.getservbyport(port) #Função da biblioteca socket que busca em uma lista os serviços
            return service
        except:
            return 'Desconhecido'
    else:
        return 'Desconhecido'

def scan_ports(ip, ports, version_check):
    """Realiza a varredura das portas e imprime os resultados."""
    abertas, fechadas, filtradas = 0, 0, 0 #Contador das portas
    portas_abertas_info = [] #Listas de portas abertas

    print(f"\nIniciando varredura no ip: {ip}")

    start_time = time.time()  # Inicia o cronômetro

    for port in ports:
        status, check_service, rtt, version = scan_port_scapy(ip, port, version_check=version_check)
        service = get_service_name(port, check_service)

        if status == 'Aberto':
            abertas += 1
            portas_abertas_info.append((port, service, version)) #Guarda as informações das portas abertas na Lista
        elif status == 'Fechado':
            fechadas += 1
        else:
            filtradas += 1

    end_time = time.time()  # Para o cronômetro
    total_time = end_time - start_time #Tempo total de execução

    print(f"\nResumo: {abertas} portas abertas, {fechadas} portas fechadas, {filtradas} portas filtradas.")
    for port, service, version in portas_abertas_info:
        version_info = version if version_check else 'Não verificado'
        print(f"Porta Aberta: {port}/tcp ({service}) - Versão: {version_info}")

    print(f"\nTempo total de execução: {total_time:.2f} segundos.")
    
if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Varredura de Portas com interface estilo RustScan.") #Adiciona argumentos na linha de comando
    parser.add_argument("ip", help="Endereço IP para escanear")
    parser.add_argument("-p", "--port", type=int, help="Número da porta específica para escanear")
    parser.add_argument("--startport", type=int, default=1, help="Número da porta inicial (padrão: 1)")
    parser.add_argument("--endport", type=int, default=1024, help="Número da porta final (padrão: 1024)")
    parser.add_argument("--version", action="store_true", help="Tenta identificar a versão do serviço nas portas abertas")

    args = parser.parse_args() #Valida os argumento adicionados
    

    if args.port:
        ports = [args.port]
    else:
        ports = range(args.startport, args.endport + 1)

    scan_ports(args.ip, ports, args.version)