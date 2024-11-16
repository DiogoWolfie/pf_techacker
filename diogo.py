import logging
import time
from random import choice, randint
import os

# Define o nome do arquivo de log com o caminho correto
log_file = os.path.join(os.getcwd(), "access.log")

# Configura o sistema de logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def generate_log():
    ip_address = f"192.168.0.{randint(1, 255)}"
    request_type = choice(["GET", "POST", "PUT", "DELETE"])
    resource = choice(["/index.html", "/about.html", "/login", "/contact", "/submit-form"])
    status_code = choice([200, 404, 500])
    response_size = randint(100, 1000)

    log_entry = f'{ip_address} - - [{time.strftime("%d/%b/%Y:%H:%M:%S")}] "{request_type} {resource} HTTP/1.1" {status_code} {response_size}'
    logging.info(log_entry)
    print(f"Log gerado: {log_entry}")

def collect_logs(file_path):
    try:
        with open(file_path, 'r') as f:
            logs = f.readlines()
        return logs
    except FileNotFoundError:
        print("Arquivo de log não encontrado!")
        return []

def main():
    try:
        while True:  # Loop infinito para gerar logs continuamente
            generate_log()
            time.sleep(2)  # Gera um novo log a cada 2 segundos
    except KeyboardInterrupt:
        # Permite sair do loop ao pressionar Ctrl+C
        print("\nEncerrando o gerador de logs...")
        logs = collect_logs(log_file)

        # Exibe os logs no console
        if logs:
            print("\nLogs coletados:")
            for log in logs:
                print(log.strip())
        else:
            print("Nenhum log foi coletado.")

if __name__ == "__main__":
    main()
