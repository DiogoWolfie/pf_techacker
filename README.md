# pf_techacker

Salve, pequeno padawan. Para usar esse código será necessário você ter as seguinte bibliotecas pyhton:
1) logging
2) datatime
3) scapy
Elas vão ajudar na análise do tráfego de rede e sua visualização.

Para rodar o código, você irá precisar rodar, em um terminal, o projetoPF.py com o comando "python .\projetoPF.py" e, em outro terminal, rodar o server.py, com o comando "python .\server.py". O server.py vai separar as informações capturadas do projetoPF.py e organizá-las em uma aplicação web para melhor entendimento do usuário.

Falando em aplicação web, nesse projeto foi usado a biblioteca flask para essa finalidade. Para ter acesso a aplicação, abra seu navegador, de preferencia o chrome, no caminho http://127.0.0.1:5000 ou http://127.0.0.1:5000/logs se quiser ter uma visualização em json.

Espero que goste do resultado.


## Compilação para linux

g++ -o packet_sniffer log_linux.cpp -L/usr/lib/x86_64-linux-gnu -lcap

Caso não funcione a compilação:

sudo apt-get install libpcap-dev

## mensagem para o professor.
Sim, fizemos apenas o C. Apesar da vontade de prosseguir com o projeto, pois parece realmente ser legal, estamos cansados. Não é só final de semestre, é o final da própria faculdade. Então, para mantermos o restante da sanidade mental que nos restou, optamos por fazer apenas essa rubrica. Espero que não se incomode.