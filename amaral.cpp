#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>

// Estrutura do cabeçalho Ethernet
struct EthernetHeader {
    u_char destMac[6];
    u_char srcMac[6];
    u_short etherType;
};

// Estrutura do cabeçalho IPv4
struct IPv4Header {
    u_char versionAndHeaderLength;
    u_char typeOfService;
    u_short totalLength;
    u_short identification;
    u_short flagsAndFragmentOffset;
    u_char timeToLive;
    u_char protocol;
    u_short checksum;
    u_char srcIp[4];
    u_char destIp[4];
};

// Estrutura do cabeçalho TCP
struct TCPHeader {
    u_short srcPort;
    u_short destPort;
    u_int sequenceNumber;
    u_int acknowledgmentNumber;
    u_char dataOffsetAndFlags;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgentPointer;
};

// Cria um arquivo HTML para salvar os logs
std::ofstream htmlFile("logs.html", std::ios::out);

void startHTML() {
    htmlFile << "<!DOCTYPE html>\n<html>\n<head>\n<title>Logs de Pacotes</title>\n</head>\n<body>\n";
    htmlFile << "<h1>Logs de Pacotes Capturados</h1>\n";
}

void endHTML() {
    htmlFile << "</body>\n</html>";
    htmlFile.close();
}

// Função para imprimir e salvar o payload no HTML
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    htmlFile << "<div style='border: 1px solid #000; margin: 10px; padding: 10px;'>";

    // Exibe o tamanho total do pacote capturado
    htmlFile << "<p><strong>Tamanho do pacote capturado:</strong> " << pkthdr->len << " bytes</p>";

    // Ethernet Header
    auto* ethHeader = (EthernetHeader*) packet;

    // Verifica se o pacote é IPv4
    if (ntohs(ethHeader->etherType) == 0x0800) {
        auto* ipHeader = (IPv4Header*) (packet + sizeof(EthernetHeader));

        // Verifica se o protocolo é TCP
        if (ipHeader->protocol == 6) { // TCP protocol number
            auto* tcpHeader = (TCPHeader*) (packet + sizeof(EthernetHeader) + sizeof(IPv4Header));

            // Calcula IPs e portas
            std::string srcIp = std::to_string(ipHeader->srcIp[0]) + "." + 
                                std::to_string(ipHeader->srcIp[1]) + "." + 
                                std::to_string(ipHeader->srcIp[2]) + "." + 
                                std::to_string(ipHeader->srcIp[3]);
            std::string destIp = std::to_string(ipHeader->destIp[0]) + "." + 
                                 std::to_string(ipHeader->destIp[1]) + "." + 
                                 std::to_string(ipHeader->destIp[2]) + "." + 
                                 std::to_string(ipHeader->destIp[3]);

            u_short srcPort = ntohs(tcpHeader->srcPort);
            u_short destPort = ntohs(tcpHeader->destPort);

            htmlFile << "<p><strong>Conexão TCP Capturada!</strong></p>";
            htmlFile << "<ul>";
            htmlFile << "<li><strong>Src IP:</strong> " << srcIp << ":" << srcPort << "</li>";
            htmlFile << "<li><strong>Dest IP:</strong> " << destIp << ":" << destPort << "</li>";
            htmlFile << "</ul>";

            // Calcula o início do payload TCP
            int ipHeaderLen = (ipHeader->versionAndHeaderLength & 0x0F) * 4;
            int tcpHeaderLen = ((tcpHeader->dataOffsetAndFlags & 0xF0) >> 4) * 4;
            const u_char* payload = packet + sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen;
            int payloadLen = pkthdr->len - (sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen);

            htmlFile << "<p><strong>Tamanho do payload:</strong> " << payloadLen << " bytes</p>";

            // Verifica se há payload
            if (payloadLen > 0) {
                std::string data(reinterpret_cast<const char*>(payload), payloadLen);

                htmlFile << "<p><strong>Payload bruto capturado (" << payloadLen << " bytes):</strong><br><code>";
                for (int i = 0; i < payloadLen; ++i) {
                    htmlFile << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i] << " ";
                }
                htmlFile << "</code></p>";

                // Verifica se é uma requisição HTTP
                if (data.find("GET") == 0 || data.find("POST") == 0 || data.find("PUT") == 0 || data.find("DELETE") == 0) {
                    std::string method = data.substr(0, data.find(" "));
                    std::string url = data.substr(data.find(" ") + 1, data.find(" HTTP/") - data.find(" ") - 1);
                    htmlFile << "<p><strong>Requisição HTTP Capturada!</strong></p>";
                    htmlFile << "<ul>";
                    htmlFile << "<li><strong>Método:</strong> " << method << "</li>";
                    htmlFile << "<li><strong>URL:</strong> " << url << "</li>";
                    htmlFile << "</ul>";
                }

                // Verifica se é uma resposta HTTP
                if (data.find("HTTP/") == 0) {
                    std::string statusCode = data.substr(data.find(" ") + 1, 3);
                    htmlFile << "<p><strong>Resposta HTTP Capturada!</strong></p>";
                    htmlFile << "<ul>";
                    htmlFile << "<li><strong>Código de Status:</strong> " << statusCode << "</li>";
                    htmlFile << "</ul>";
                }
            } else if (destPort == 443 || srcPort == 443) {
                htmlFile << "<p>Conexão HTTPS detectada.</p>";
            }
        }
    }

    htmlFile << "</div>";
}

// Função principal
int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *device;

    if (pcap_findalldevs(&interfaces, errorBuffer) == -1) {
        std::cerr << "Erro ao encontrar dispositivos: " << errorBuffer << std::endl;
        return 1;
    }

    int idx = 0;
    for (device = interfaces; device != nullptr; device = device->next) {
        std::cout << ++idx << ": " << device->name << " - " << (device->description ? device->description : "Sem descrição") << std::endl;
    }

    int selectedInterface;
    std::cout << "Escolha a interface (1-" << idx << "): ";
    std::cin >> selectedInterface;

    device = interfaces;
    for (int i = 1; i < selectedInterface; ++i) {
        device = device->next;
    }

    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, true, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Erro ao abrir dispositivo: " << errorBuffer << std::endl;
        pcap_freealldevs(interfaces);
        return 1;
    }

    startHTML();

    struct bpf_program filter;
    std::string filterExp = "tcp";
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Erro ao definir filtro de captura: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(interfaces);
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);

    endHTML();

    pcap_freealldevs(interfaces);
    pcap_close(handle);
    return 0;
}
