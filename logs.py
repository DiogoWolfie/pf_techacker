from scapy.all import sniff

# Função de callback para processar cada pacote
def process_packet(packet):
    if packet.haslayer("IP"):
        print(f"Pacote IP: {packet['IP'].src} -> {packet['IP'].dst}")
    if packet.haslayer("TCP") and packet.haslayer("Raw"):
        print(f"Dados HTTPS: {packet['Raw'].load}")

# Captura pacotes em tempo real
print("Capturando pacotes em tempo real...")
sniff(filter="tcp port 443", prn=process_packet)
