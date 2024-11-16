#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <string>

// Estruturas de cabeçalho Ethernet, IP e TCP
struct EthernetHeader {
    u_char dest[6];
    u_char src[6];
    u_short etherType;
};

struct IPv4Header {
    u_char versionAndHeaderLength;
    u_char typeOfService;
    u_short totalLength;
    u_short identification;
    u_short flagsAndFragmentOffset;
    u_char timeToLive;
    u_char protocol;
    u_short headerChecksum;
    u_char srcIp[4];
    u_char destIp[4];
};

struct TCPHeader {
    u_short srcPort;
    u_short destPort;
    u_int sequenceNumber;
    u_int ackNumber;
    u_char dataOffsetAndFlags;
    u_char flags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
};

// Função para salvar conteúdo no HTML
void save_to_html(const std::string& content) {
    std::ofstream htmlFile("packets.html", std::ios::app);
    if (!htmlFile.is_open()) {
        std::cerr << "Erro ao abrir o arquivo HTML.\n";
        return;
    }

    htmlFile << content;
    htmlFile.close();
}

// Função para processar os pacotes capturados
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* ethHeader = (EthernetHeader*) packet;

    if (ntohs(ethHeader->etherType) == 0x0800) { // Verifica se é IPv4
        auto* ipHeader = (IPv4Header*) (packet + sizeof(EthernetHeader));

        if (ipHeader->protocol == 6) { // Verifica se é TCP
            auto* tcpHeader = (TCPHeader*) (packet + sizeof(EthernetHeader) + sizeof(IPv4Header));

            // IPs e portas
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

            // Cálculo do tamanho do payload
            int ipHeaderLen = (ipHeader->versionAndHeaderLength & 0x0F) * 4;
            int tcpHeaderLen = ((tcpHeader->dataOffsetAndFlags & 0xF0) >> 4) * 4;
            const u_char* payload = packet + sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen;
            int payloadLen = pkthdr->len - (sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen);

            // Determina o tipo de requisição
            std::string requestType = "Não HTTP";
            if (payloadLen > 0) {
                std::string payloadStr(reinterpret_cast<const char*>(payload), payloadLen);
                if (payloadStr.find("GET ") == 0 || payloadStr.find("POST ") == 0 || 
                    payloadStr.find("PUT ") == 0 || payloadStr.find("DELETE ") == 0) {
                    requestType = "HTTP Requisição";
                } else if (payloadStr.find("HTTP/1.") == 0) {
                    requestType = "HTTP Resposta";
                }
            }

            // Monta o conteúdo para o HTML
            std::ostringstream htmlContent;
            htmlContent << "<tr>"
                        << "<td>TCP</td>"
                        << "<td>" << srcIp << "</td>"
                        << "<td>" << srcPort << "</td>"
                        << "<td>" << destIp << "</td>"
                        << "<td>" << destPort << "</td>"
                        << "<td>" << payloadLen << " bytes</td>"
                        << "<td>" << requestType << "</td>"
                        << "</tr>\n";

            save_to_html(htmlContent.str());

            // Exibição no terminal
            std::cout << "Pacote TCP capturado: \n"
                      << "  IP Origem: " << srcIp << "\n"
                      << "  Porta Origem: " << srcPort << "\n"
                      << "  IP Destino: " << destIp << "\n"
                      << "  Porta Destino: " << destPort << "\n"
                      << "  Tamanho do Payload: " << payloadLen << " bytes\n"
                      << "  Tipo de Requisição: " << requestType << "\n\n";
        }
    }
}

// Função principal
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Erro ao listar dispositivos: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Dispositivos disponíveis:\n";
    pcap_if_t* device;
    for (device = devices; device; device = device->next) {
        std::cout << "- " << device->name << "\n";
    }

    char deviceName[100];
    std::cout << "\nDigite o nome do dispositivo para capturar pacotes: ";
    std::cin >> deviceName;

    pcap_t* handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Erro ao abrir o dispositivo: " << errbuf << "\n";
        return 1;
    }

    // Inicializa o arquivo HTML
    std::ofstream htmlFile("packets.html");
    htmlFile << "<html><head><title>Pacotes Capturados</title></head><body>\n";
    htmlFile << "<table border='1'>\n";
    htmlFile << "<thead><tr><th>Protocolo</th><th>IP Origem</th><th>Porta Origem</th>"
             << "<th>IP Destino</th><th>Porta Destino</th><th>Tamanho do Payload</th>"
             << "<th>Tipo de Requisição</th></tr></thead><tbody>\n";
    htmlFile.close();

    // Captura pacotes
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Finaliza o HTML
    htmlFile.open("packets.html", std::ios::app);
    htmlFile << "</tbody></table></body></html>\n";
    htmlFile.close();

    pcap_close(handle);
    return 0;
}
