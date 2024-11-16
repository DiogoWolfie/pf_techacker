# pf_techacker

Olha só, progresso. O código log_npcap compilou e está me retornando c0isas úteis, como ips e portas.
Só que como https é criptografado, ele só consegue dizer se foi uma requisição do tipo, e mais nada.


## Compilação para linux

g++ -o packet_sniffer log_linux.cpp -L/usr/lib/x86_64-linux-gnu -lcap

Caso não funcione a compilação:

sudo apt-get install libpcap-dev