#include <pcap.h>
#include <iostream>
#include <winsock2.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "Pacote Capturado: Tamanho " << pkthdr->len << " bytes" << std::endl;

    // Exibe o conteúdo do pacote
    for (int i = 0; i < pkthdr->len; ++i) {
        std::cout << std::hex << (int)packet[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;
}

int main() {
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

    // Configura filtro para capturar apenas pacotes TCP
    // struct bpf_program filter;
    // std::string filterExp = "tcp";
    // if (pcap_compile(handle, &filter, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
    //     pcap_setfilter(handle, &filter) == -1) {
    //     std::cerr << "Erro ao definir filtro de captura: " << pcap_geterr(handle) << std::endl;
    //     pcap_freealldevs(interfaces);
    //     pcap_close(handle);
    //     return 1;
    // }

    // Captura pacotes
    std::cout << "Capturando pacotes na interface " << device->name << std::endl;
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Libera recursos
    pcap_freealldevs(interfaces);
    pcap_close(handle);
    return 0;
}
