#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
using namespace std;

int main(){
    //inicializa o winsock
    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if(result !=0){
        cerr << "WSAStartup falhou" << result << endl;
        return 1;
    }

    //cria um socket
    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(connectSocket == INVALID_SOCKET){
        cerr << "Erro ao criar socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    //configurando o endereço do servidor
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(80); //http
    
    inet_pton(AF_INET, "192.168.56.1", &serverAddr.sin_addr); //ip do meu localhost

    //conectando ao servidor
    result = connect(connectSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    if(result == SOCKET_ERROR){
        cerr << "Falha ao conectar: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    //enviando uma requisição http GET
    string request = "GET / HTTP/1.1\r\nHost: 192.168.56.1\r\nConnection: close\r\n\r\n";
    result = send(connectSocket, request.c_str(), request.length(), 0);
    if(result == SOCKET_ERROR){
        cerr << "Erro ao enviar: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }

    //recebendo a resposta
    char buffer[1024];
    do{
        result = recv(connectSocket, buffer, sizeof(buffer)-1, 0);
        if (result > 0) {
            buffer[result] = '\0';  // Adiciona null terminator para exibir como string
            cout << buffer;  // Exibe os logs no prompt
        } else if (result == 0) {
            cout << "Conexão fechada." << std::endl;
        } else {
            cerr << "Erro ao receber: " << WSAGetLastError() << std::endl;
        }
    }while (result > 0);
    
    //limpando os recursos
    closesocket(connectSocket);
    WSACleanup();
    return 0;
}