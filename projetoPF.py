import logging
from scapy.all import sniff, IP, TCP
from datetime import datetime

# Limpa o arquivo de logs ao iniciar, nele vc pode ver o que estamos retornando
open("access.log", "w").close()

# Configuração de logging
logging.basicConfig(
    filename="access.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def extract_http_payload(packet):
    """Extrai o payload HTTP de pacotes TCP."""
    if TCP in packet:
        payload = bytes(packet[TCP].payload).decode(errors="ignore")
        if "HTTP" in payload:  
            return payload
    return None

def process_packet(packet):
    """Processa pacotes capturados e gera logs reais."""
    if IP in packet and TCP in packet:  
        ip_src = packet[IP].src
        ip_dest = packet[IP].dst
        port_src = packet[TCP].sport
        port_dest = packet[TCP].dport
        protocol = "TCP"
        payload_size = len(packet[TCP].payload) if packet[TCP].payload else 0

        # Extrai payload HTTP, se existir
        http_payload = extract_http_payload(packet)
        http_method = None
        http_status = None
        if http_payload:
            
            lines = http_payload.split("\r\n")
            if len(lines) > 0 and lines[0]:
                http_method = lines[0].split(" ")[0]
            if "HTTP/" in lines[-1]:  
                http_status = lines[-1].split(" ")[1] if len(lines[-1].split(" ")) > 1 else "N/A"

        # Converte o tempo do pacote para um formato legível
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        log_entry = (f"{timestamp} - {ip_src}:{port_src} -> {ip_dest}:{port_dest} - - "
                     f"[{protocol}] - {payload_size} bytes - "
                     f"{http_method if http_method else 'UNKNOWN'} - "
                     f"Status: {http_status if http_status else 'N/A'}")
        logging.info(log_entry)
        print(f"Log capturado: {log_entry}")

def main():
    print("Iniciando captura de pacotes... Pressione Ctrl+C para encerrar.")
    try:
        # Captura apenas pacotes TCP
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nEncerrando captura de pacotes.")

if __name__ == "__main__":
    main()
