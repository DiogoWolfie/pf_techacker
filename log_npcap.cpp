#include <pcap.h> //biblioteca de captura de pacotes
#include <iostream>
#include <iomanip>
#include <winsock2.h> //inclui funções de rede específicas para o Windows
#include <ws2tcpip.h>
#include <string>

// Substituição para inet_ntop no Windows
const char* inet_ntop(int af, const void* src, char* dst, size_t size) {
    if (af == AF_INET) {
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr, src, sizeof(in_addr));
        if (WSAAddressToStringA((sockaddr*)&addr, sizeof(sockaddr_in), nullptr, dst, (LPDWORD)&size) == 0) {
            return dst;
        }
    }
    return nullptr;
}

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

// Função para imprimir o payload em um formato legível
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
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

            std::cout << "Conexão TCP Capturada!" << std::endl;
            std::cout << "   Src IP: " << srcIp << ":" << srcPort << std::endl;
            std::cout << "   Dest IP: " << destIp << ":" << destPort << std::endl;

            // Calcula o início do payload TCP
            int ipHeaderLen = (ipHeader->versionAndHeaderLength & 0x0F) * 4;
            int tcpHeaderLen = ((tcpHeader->dataOffsetAndFlags & 0xF0) >> 4) * 4;
            const u_char* payload = packet + sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen;
            int payloadLen = pkthdr->len - (sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen);

            // Verifica se há payload (dados da aplicação)
            if (payloadLen > 0) {
                std::string data(reinterpret_cast<const char*>(payload), payloadLen);

                std::cout << "Payload bruto capturado (" << payloadLen << " bytes): ";
                for (int i = 0; i < payloadLen; ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i] << " ";
                }
                std::cout << std::dec << std::endl; // Volta para decimal

                // Verifica se é uma requisição HTTP
                if (data.find("GET") == 0 || data.find("POST") == 0 || data.find("PUT") == 0 || data.find("DELETE") == 0) {
                    std::string method = data.substr(0, data.find(" "));
                    std::string url = data.substr(data.find(" ") + 1, data.find(" HTTP/") - data.find(" ") - 1);
                    std::cout << "Requisição HTTP Capturada!" << std::endl;
                    std::cout << "   Método: " << method << std::endl;
                    std::cout << "   URL: " << url << std::endl;
                }

                // Verifica se é uma resposta HTTP
                if (data.find("HTTP/") == 0) {
                    std::string statusCode = data.substr(data.find(" ") + 1, 3);
                    std::cout << "Resposta HTTP Capturada!" << std::endl;
                    std::cout << "   Código de Status: " << statusCode << std::endl;
                }
            } else if (destPort == 443 || srcPort == 443) {
                // Caso seja HTTPS
                std::cout << "Conexão HTTPS detectada." << std::endl;
            }
        }
    }
    //std::cout << "----------------------------------------" << std::endl;
}



int main() {
    // Inicializando o Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Erro ao inicializar o Winsock." << std::endl;
        return 1;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *device;
    int count = 0;

    // Lista todas as interfaces de rede disponíveis
    if (pcap_findalldevs(&interfaces, errorBuffer) == -1) {
        std::cerr << "Erro ao encontrar dispositivos: " << errorBuffer << std::endl;
        return 1;
    }

    // Mostra as interfaces e permite ao usuário escolher uma
    int idx = 0;
    for (device = interfaces; device != nullptr; device = device->next) {
        std::cout << ++idx << ": " << device->name << " - " << (device->description ? device->description : "No description") << std::endl;
    }
    
    int selectedInterface = 0;
    std::cout << "Escolha a interface (1-" << idx << "): ";
    std::cin >> selectedInterface;
    if (selectedInterface < 1 || selectedInterface > idx) {
        std::cerr << "Interface inválida selecionada." << std::endl;
        pcap_freealldevs(interfaces);
        return 1;
    }

    // Seleciona a interface escolhida pelo usuário
    device = interfaces;
    for (int i = 1; i < selectedInterface; ++i) {
        device = device->next;
    }

    // Abre a interface para captura
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, true, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Erro ao abrir dispositivo: " << errorBuffer << std::endl;
        pcap_freealldevs(interfaces);
        return 1;
    }

    // Configura filtro para capturar apenas pacotes TCP nas portas 80 ou 443
    struct bpf_program filter;
    //std::string filterExp = "tcp port 80 or tcp port 443";
    std::string filterExp = "tcp";
    if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Erro ao definir filtro de captura: " << pcap_geterr(handle) << std::endl;
        pcap_freealldevs(interfaces);
        pcap_close(handle);
        return 1;
    }

    // Captura pacotes
    std::cout << "Capturando pacotes na interface " << device->name << std::endl;
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Libera recursos
    pcap_freealldevs(interfaces);
    pcap_close(handle);
    WSACleanup();
    return 0;
}
