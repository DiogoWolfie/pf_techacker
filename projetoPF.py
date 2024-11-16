import logging
from scapy.all import sniff, IP, TCP, UDP

# Limpa o arquivo de logs ao iniciar
open("access.log", "w").close()

# Configuração de logging
logging.basicConfig(
    filename="access.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def process_packet(packet):
    """Processa pacotes capturados e gera logs reais."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dest = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        port_src = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "-"
        port_dest = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "-"
        payload_size = len(packet[IP].payload) if packet[IP].payload else 0

        log_entry = (f"{packet.time:.3f} - {ip_src}:{port_src} -> {ip_dest}:{port_dest} - - "
                     f"[{protocol}] - {payload_size} bytes")
        logging.info(log_entry)
        print(f"Log capturado: {log_entry}")

def main():
    print("Iniciando captura de pacotes... Pressione Ctrl+C para encerrar.")
    try:
        sniff(filter="ip", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nEncerrando captura de pacotes.")

if __name__ == "__main__":
    main()
