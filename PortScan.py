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
 ____  ____  _____         ____                 
|  _ \|  _ \|  ___|       / ___|  ___ __ _ _ __ 
| |_) | | | | |_   _____  \___ \ / __/ _` | '_ \
|  __/| |_| |  _| |_____|  ___) | (_| (_| | | | |
|_|   |____/|_|           |____/ \___\__,_|_| |_|
    """
    print(banner)

def get_service_version(ip, port):
    """Tenta obter a versão do serviço na porta especificada."""
    version_info = 'Desconhecido'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            s.sendall(b"VERSION\r\n")
            response = s.recv(1024).decode()
            version_info = response.strip() if response else version_info
    except socket.error as e:
        version_info = f"Erro de socket: {e}"
    except Exception as e:
        version_info = f"Erro geral: {e}"
    return version_info

def scan_port_scapy(ip, port, timeout=2, retries=1, verbose=False):
    """Escaneia uma única porta usando Scapy e retorna o status, RTT e versão do serviço."""
    for _ in range(retries):
        try:
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
            start_time = time.time()
            response = sr1(packet, timeout=timeout, verbose=0)
            rtt = time.time() - start_time

            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    if verbose:
                        print(f"Porta {port}/tcp: Aberto (RTT: {rtt:.2f}s)")
                    version = get_service_version(ip, port) if verbose else 'Versão não verificada'
                    return 'Aberto', True, rtt, version
                elif response.getlayer(TCP).flags == 0x14:
                    if verbose:
                        print(f"Porta {port}/tcp: Fechado (RTT: {rtt:.2f}s)")
                    return 'Fechado', False, rtt, None
        except Exception as e:
            if verbose:
                print(f"Erro na porta {port}: {e}")
            logging.error(f"Erro ao escanear a porta {port}: {e}")
    return 'Filtrado', True, None, None

def get_service_name(port, check_service):
    """Obtém o nome do serviço para a porta especificada, se possível."""
    if check_service:
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return 'Desconhecido'
    else:
        return 'Desconhecido'

def scan_ports(ip, ports, verbose, version_check):
    """Realiza a varredura das portas e imprime os resultados."""
    abertas, fechadas, filtradas = 0, 0, 0
    portas_abertas_info = []

    print(f"\nIniciando varredura no ip: {ip}")
    if verbose:
        print("PORTA\tESTADO\tSERVIÇO\tRTT\tVERSÃO")

    for port in ports:
        status, check_service, rtt, version = scan_port_scapy(ip, port, verbose=verbose)
        service = get_service_name(port, check_service)
        version_info = version if version_check else 'Não verificado'

        if verbose:
            rtt_info = f'{rtt:.2f}s' if rtt is not None else 'N/A'
            print(f"{port}/tcp\t{status}\t{service}\t{rtt_info}\t{version_info}")

        if status == 'Aberto':
            abertas += 1
            portas_abertas_info.append((port, service, version))
        elif status == 'Fechado':
            fechadas += 1
        else:
            filtradas += 1

    print(f"\nResumo: {abertas} portas abertas, {fechadas} portas fechadas, {filtradas} portas filtradas.")
    for port, service, version in portas_abertas_info:
        version_info = version if version_check else 'Não verificado'
        print(f"Porta Aberta: {port}/tcp ({service}) - Versão: {version_info}")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Varredura de Portas com interface estilo RustScan.")
    parser.add_argument("ip", help="Endereço IP para escanear")
    parser.add_argument("-p", "--port", type=int, help="Número da porta específica para escanear")
    parser.add_argument("--startport", type=int, default=1, help="Número da porta inicial (padrão: 1)")
    parser.add_argument("--endport", type=int, default=1024, help="Número da porta final (padrão: 1024)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Ativa a varredura detalhada")
    parser.add_argument("--version", action="store_true", help="Tenta identificar a versão do serviço nas portas abertas")

    args = parser.parse_args()

    if args.port:
        ports = [args.port]
    else:
        ports = range(args.startport, args.endport + 1)

    scan_ports(args.ip, ports, args.verbose, args.version)