import logging
import time
from random import choice, randint

# Limpa o arquivo de logs ao iniciar
open("access.log", "w").close()

logging.basicConfig(
    filename='access.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def generate_log():
    ip_src = f"192.168.0.{randint(1, 255)}"
    port_src = randint(1000, 65000)
    ip_dest = "192.168.1.1"
    port_dest = randint(1000, 65000)
    request_type = choice(["GET", "POST", "PUT", "DELETE"])
    resource = choice(["/index.html", "/about.html", "/login", "/contact", "/submit-form"])
    status_code = choice([200, 404, 500])
    response_size = randint(100, 1000)

    log_entry = (f"{time.strftime('%Y-%m-%d %H:%M:%S')},000 - {ip_src}:{port_src} -> {ip_dest}:{port_dest} - - "
                 f"[{time.strftime('%d/%b/%Y:%H:%M:%S')}] \"{request_type} {resource} HTTP/1.1\" {status_code} {response_size}")
    logging.info(log_entry)
    print(f"Log gerado: {log_entry}")

def main():
    try:
        while True:
            generate_log()
            time.sleep(2)
    except KeyboardInterrupt:
        print("Encerrando geração de logs.")

if __name__ == "__main__":
    main()
