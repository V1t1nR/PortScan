PortScan Script
Este repositório contém PortScan.py, um script de varredura de portas desenvolvido em Python. Ele permite identificar portas abertas, fechadas ou filtradas em um endereço IP específico, com opções para varredura de uma única porta ou um intervalo de portas.

Pré-requisitos
Para executar o script PortScan.py, é necessário ter o Python 3 instalado no sistema. O script install_dependencies.sh fornecido cuida da instalação de todas as dependências necessárias, incluindo Python 3, pip3 e a biblioteca Scapy.

Instalação
Para instalar as dependências e configurar o ambiente, siga as instruções abaixo:

Clone o repositório:

bash
Copy code
git clone https://github.com/seu_usuario/seu_repositorio.git](https://github.com/V1t1nR/PortScan.git
cd seu_repositorio
Torne o script install_dependencies.sh executável:

bash
Copy code
chmod +x install_dependencies.sh
Execute o script install_dependencies.sh para instalar as dependências necessárias:

bash
Copy code
./install_dependencies.sh
Uso
Após a instalação, o script PortScan.py pode ser utilizado diretamente do terminal como um comando:

css
Copy code
portscan <endereço IP> [--port <número da porta>] [--startport <porta inicial>] [--endport <porta final>] [-v]
Opções de Comando:
<endereço IP>: Endereço IP do alvo para a varredura de portas.
--port <número da porta>: Especifica uma única porta para varrer (opcional).
--startport <porta inicial>: Define a porta inicial para um intervalo de varredura (padrão: 1).
--endport <porta final>: Define a porta final para um intervalo de varredura (padrão: 1024).
-v, --verbose: Ativa o modo detalhado (verbose), mostrando informações detalhadas sobre cada porta escaneada.


Contribuições
Contribuições para o projeto são bem-vindas. Sinta-se à vontade para criar um fork do repositório, fazer suas alterações e enviar uma pull request.
