#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <map>
#include <arpa/inet.h>
#include "header.h"

using namespace std;

void usage(){
    printf("usage  : pcap_stat <pcap file name>\n");
    printf("example: pcap_stat test.pcap\n");
}

int main(int argc, char * argv[]){

    if(argc < 2){
        usage();
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open file %s: %s\n", argv[1], errbuf);
        return -1;
    }

    map<IP_key, values> ip_conv;
    map<MAC_key, values> mac_conv;

    map<uint32_t, values> ip_end;
    map<MAC, values> mac_end;

    while(handle != NULL){
        struct pcap_pkthdr* header;
        const u_char* data;

        int res = pcap_next_ex(handle, &header, &data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        
        Packet * packet = (Packet *)data;
        IP_key ip_key;
        MAC_key mac_key;

        if(ntohs(packet->eth.ether_type) == 0x0800){
            ip_key.src_ip = packet->ip.src_ip;
            ip_key.dst_ip = packet->ip.dst_ip;
            ip_conversations(ip_conv, ip_key, header);
        }

        memcpy(mac_key.src_mac, packet->eth.src_MAC, sizeof(mac_key.src_mac));
        memcpy(mac_key.dst_mac, packet->eth.dst_MAC, sizeof(mac_key.dst_mac));

        mac_conversations(mac_conv, mac_key, header);

    }printf("\n");
    pcap_close(handle);
    
    join_ip_conversations(ip_conv);
    join_mac_conversations(mac_conv);

    ip_endpoints(ip_end, ip_conv);
    mac_endpoints(mac_end, mac_conv);

    int menu, layer;
    
    while(1){
        printf("=====================================================\n");
        printf("=             pcap statistics(exit: 3)              =\n");
        printf("=====================================================\n");
        printf("=       1.Conversations          2.Endpoints        =\n");
        printf("=====================================================\n");
        scanf("%d", &menu);
        if(menu == 3){ return 0; }
        if(menu < 1 || menu > 2){
            printf("[-] Invalid Input\n");
        }
        printf("=====================================================\n");
        printf("=       1.IP                     2.MAC              =\n");
        printf("=====================================================\n");
        scanf("%d", &layer);
        if(layer == 3){ return 0; }
        if(layer < 1 || layer > 3){
            printf("[-] Invalid Input\n");
        }else{
            if(menu == 1){
                if(layer == 1){
                    printf("=====================================================\n");
                    printf("=                IP Conversations                   =\n");
                    print_ip_conversations(ip_conv);
                }else if(layer == 2){
                    printf("=====================================================\n");
                    printf("=               MAC Conversations                   =\n");
                    print_mac_conversations(mac_conv);
                }
            }else if(menu == 2){
                if(layer == 1){
                    printf("=====================================================\n");
                    printf("=                  IP Endpoints                     =\n");
                    print_ip_endpoints(ip_end);
                }else if(layer == 2){
                    printf("=====================================================\n");
                    printf("=                 MAC Endpoints                     =\n");
                    print_mac_endpoints(mac_end);
                }
            }
        } 
    }
    return 0;
}
