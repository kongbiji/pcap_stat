#pragma once
#include <stdint.h>
#include <string.h>
#include <map>

using namespace std;

#pragma pack(push,1)
typedef struct ETHER{
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
}Ether;
typedef struct IP{
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;
typedef struct packet{
    Ether eth;
    IP ip;
}Packet;

typedef struct MAC{
    uint8_t mac[6];
    bool operator <(const MAC& var) const
    {
        return memcmp(mac, var.mac, sizeof(mac)) < 0;
    }
}MAC;

typedef struct MAC_key{
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    bool operator <(const MAC_key& var) const
    {
        if(memcmp(src_mac, var.src_mac, sizeof(src_mac)) != 0){
            return memcmp(src_mac, var.src_mac, sizeof(src_mac)) < 0;
        }else{
            return memcmp(dst_mac, var.dst_mac, sizeof(dst_mac)) < 0;
        }
    }
}MAC_key;

typedef struct IP_key{
    uint32_t src_ip;
    uint32_t dst_ip;
    bool operator <(const IP_key& var) const
    {
        if(src_ip != var.src_ip){
            return src_ip < var.src_ip;
        }else{
            return dst_ip < var.dst_ip;
        }
    }
}IP_key;

typedef struct {
    unsigned int Tx_packets;
    unsigned int Tx_bytes;
    unsigned int Rx_packets;
    unsigned int Rx_bytes;
    unsigned int total_packets;
    unsigned int total_bytes;
} values;
#pragma pack(pop)

// IP conversations function
void ntoa(uint32_t ip, char * dst){ 
    sprintf(dst, "%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}
void ip_conversations(map<IP_key, values>&conv, IP_key key, struct pcap_pkthdr* header){
    map<IP_key, values>::iterator iter;
    iter = conv.find(key);
    if(iter == conv.end()){

        values val;
        val.Rx_bytes = 0;
        val.Rx_packets = 0;
        val.total_packets = 1;
        val.total_bytes = header->caplen;
        val.Tx_packets = 1;
        val.Tx_bytes = header->caplen;

        conv.insert(pair<IP_key, values>(key, val));

    }else{
        iter->second.Tx_packets++;
        iter->second.Tx_bytes += header->caplen;
        iter->second.total_packets++;
        iter->second.total_bytes += header->caplen;
    }
}
void join_ip_conversations(map<IP_key, values>&conv){
    map<IP_key, values>::iterator iter;

    for(iter = conv.begin(); iter != conv.end(); ++iter){
        IP_key key;
        key.src_ip = iter->first.dst_ip;
        key.dst_ip = iter->first.src_ip;

        map<IP_key, values>::iterator inner_iter = conv.find(key);
        if( inner_iter != conv.end()){
            iter->second.Rx_bytes += inner_iter->second.Tx_bytes;
            iter->second.Rx_packets += inner_iter->second.Tx_packets;
            iter->second.total_bytes += inner_iter->second.total_bytes;
            iter->second.total_packets += inner_iter->second.total_packets;
            conv.erase(inner_iter);
        }
    }
}
void print_ip_conversations(map<IP_key, values>&conv){
    map<IP_key, values>::iterator iter;
    for(iter = conv.begin(); iter != conv.end(); ++iter){
        printf("=====================================================\n");
        char src[18], dst[18];
        ntoa((*iter).first.src_ip, src);
        ntoa((*iter).first.dst_ip, dst);

        printf("addr A( %s ) <-> addr B( %s )\n", src, dst);
        printf("total   packets / bytes: %d / %d\n",(*iter).second.total_packets,(*iter).second.total_bytes);
        printf("A -> B  packets / bytes: %d / %d\n", (*iter).second.Tx_packets, (*iter).second.Tx_bytes);
        printf("B -> A  packets / bytes: %d / %d\n", (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
    }
    printf("=====================================================\n");
}
// IP endpoints function
void convert_conv_to_end(map<uint32_t, values>&end, map<IP_key, values>&conv, uint32_t key, values val){
    map<IP_key, values>::iterator inner_iter;
    for(inner_iter = conv.begin(); inner_iter != conv.end(); ++inner_iter){
           if(key == inner_iter->first.src_ip){
                val.Tx_bytes += inner_iter->second.Tx_bytes;
                val.Tx_packets += inner_iter->second.Tx_packets;
                val.Rx_bytes += inner_iter->second.Rx_bytes;
                val.Rx_packets += inner_iter->second.Rx_packets;
                val.total_bytes += inner_iter->second.total_bytes;
                val.total_packets += inner_iter->second.total_packets;
            }
            if(key == inner_iter->first.dst_ip){
                val.Tx_bytes += inner_iter->second.Rx_bytes;
                val.Tx_packets += inner_iter->second.Rx_packets;
                val.Rx_bytes += inner_iter->second.Tx_bytes;
                val.Rx_packets += inner_iter->second.Tx_packets;
                val.total_bytes += inner_iter->second.total_bytes;
                val.total_packets += inner_iter->second.total_packets;
            }
        }
        end.insert(pair<uint32_t, values>(key, val));
}
void ip_endpoints(map<uint32_t, values>&end, map<IP_key, values>&conv){
    map<IP_key, values>::iterator iter;
    for(iter = conv.begin(); iter != conv.end(); ++iter){
        uint32_t tkey = iter->first.src_ip;
        uint32_t rkey = iter->first.dst_ip;
        values tval, rval;
        
        if(end.find(tkey) == end.end()){
            tval.Tx_bytes = 0;
            tval.Tx_packets = 0;
            tval.Rx_bytes = 0;
            tval.Rx_packets = 0;
            tval.total_bytes = 0;
            tval.total_packets = 0;
        }
        convert_conv_to_end(end, conv, tkey, tval);

        if(end.find(rkey) == end.end()){
            rval.Tx_bytes = 0;
            rval.Tx_packets = 0;
            rval.Rx_bytes = 0;
            rval.Rx_packets = 0;
            rval.total_bytes = 0;
            rval.total_packets = 0;
        }
        convert_conv_to_end(end, conv, rkey,rval);
    }
}
void print_ip_endpoints(map<uint32_t, values>&end){
    map<uint32_t, values>::iterator iter;
    for(iter = end.begin(); iter != end.end(); ++iter){
        printf("=====================================================\n");
        char addr[18];
        ntoa((*iter).first, addr);

        printf("addr ( %s )\n", addr);
        printf("total packets / bytes: %d / %d\n",(*iter).second.total_packets,(*iter).second.total_bytes);
        printf("Tx    packets / bytes: %d / %d\n", (*iter).second.Tx_packets, (*iter).second.Tx_bytes);
        printf("Rx    packets / bytes: %d / %d\n", (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
    }
    printf("=====================================================\n");
}

// MAC conversations function
void print_MAC(const uint8_t *addr){
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5]);
}
void mac_conversations(map<MAC_key, values>&conv, MAC_key key, struct pcap_pkthdr* header){
    map<MAC_key, values>::iterator iter;
    iter = conv.find(key);
    if(iter == conv.end()){
        values var;
        var.Rx_bytes = 0;
        var.Rx_packets = 0;
        var.total_packets = 1;
        var.total_bytes = header->caplen;
        var.Tx_packets = 1;
        var.Tx_bytes = header->caplen;

        conv.insert(pair<MAC_key, values>(key, var));

    }else{
        iter->second.Tx_packets++;
        iter->second.Tx_bytes += header->caplen;
        iter->second.total_packets++;
        iter->second.total_bytes += header->caplen;
    }
}
void join_mac_conversations(map<MAC_key, values>&conv){
    map<MAC_key, values>::iterator iter;

    for(iter = conv.begin(); iter != conv.end(); ++iter){
        MAC_key key;
        memcpy(key.src_mac, iter->first.dst_mac, sizeof(key.src_mac));
        memcpy(key.dst_mac, iter->first.src_mac, sizeof(key.dst_mac));

        map<MAC_key, values>::iterator inner_iter = conv.find(key);
        if( inner_iter != conv.end()){
            iter->second.Rx_bytes += inner_iter->second.Tx_bytes;
            iter->second.Rx_packets += inner_iter->second.Tx_packets;
            iter->second.total_bytes += inner_iter->second.total_bytes;
            iter->second.total_packets += inner_iter->second.total_packets;
            conv.erase(inner_iter);
        }
    }
}
void print_mac_conversations(map<MAC_key, values>&conv){
    map<MAC_key, values>::iterator iter;
    for(iter = conv.begin(); iter != conv.end(); ++iter){
        printf("=====================================================\n");

        printf("addr A( "); print_MAC(iter->first.src_mac); printf(") <-> addr B( "); print_MAC(iter->first.dst_mac); printf(" )\n");
        printf("total   packets / bytes: %d / %d\n",(*iter).second.total_packets,(*iter).second.total_bytes);
        printf("A -> B  packets / bytes: %d / %d\n", (*iter).second.Tx_packets, (*iter).second.Tx_bytes);
        printf("B -> A  packets / bytes: %d / %d\n", (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
    }
    printf("=====================================================\n");
}

// MAC endpoints function
void convert_mac_conv_to_end(map<MAC, values>&end, map<MAC_key, values>&conv, MAC key, values val){
    map<MAC_key, values>::iterator inner_iter;
    for(inner_iter = conv.begin(); inner_iter != conv.end(); ++inner_iter){
           if(memcmp(key.mac, inner_iter->first.src_mac, sizeof(key))){
                val.Tx_bytes += inner_iter->second.Tx_bytes;
                val.Tx_packets += inner_iter->second.Tx_packets;
                val.Rx_bytes += inner_iter->second.Rx_bytes;
                val.Rx_packets += inner_iter->second.Rx_packets;
                val.total_bytes += inner_iter->second.total_bytes;
                val.total_packets += inner_iter->second.total_packets;
            }
            if(memcmp(key.mac, inner_iter->first.dst_mac, sizeof(key))){
                val.Tx_bytes += inner_iter->second.Rx_bytes;
                val.Tx_packets += inner_iter->second.Rx_packets;
                val.Rx_bytes += inner_iter->second.Tx_bytes;
                val.Rx_packets += inner_iter->second.Tx_packets;
                val.total_bytes += inner_iter->second.total_bytes;
                val.total_packets += inner_iter->second.total_packets;
            }
        }
        end.insert(pair<MAC, values>(key, val));
}
void mac_endpoints(map<MAC, values>&end, map<MAC_key, values>&conv){
    map<MAC_key, values>::iterator iter;
    for(iter = conv.begin(); iter != conv.end(); ++iter){
        MAC tkey, rkey;
        values tval, rval;

        memcpy(tkey.mac, iter->first.src_mac, sizeof(tkey));
        memcpy(rkey.mac, iter->first.dst_mac, sizeof(rkey));

        if(end.find(tkey) == end.end()){
            tval.Tx_bytes = 0;
            tval.Tx_packets = 0;
            tval.Rx_bytes = 0;
            tval.Rx_packets = 0;
            tval.total_bytes = 0;
            tval.total_packets = 0;
        }
        convert_mac_conv_to_end(end, conv, tkey, tval);

        if(end.find(rkey) == end.end()){
            rval.Tx_bytes = 0;
            rval.Tx_packets = 0;
            rval.Rx_bytes = 0;
            rval.Rx_packets = 0;
            rval.total_bytes = 0;
            rval.total_packets = 0;
        }
        convert_mac_conv_to_end(end, conv, rkey,rval);
    }
}
void print_mac_endpoints(map<MAC, values>&end){
    map<MAC, values>::iterator iter;
    for(iter = end.begin(); iter != end.end(); ++iter){
        printf("=====================================================\n");

        printf("addr ( "); print_MAC(iter->first.mac); printf(" )\n");
        printf("total packets / bytes: %d / %d\n",(*iter).second.total_packets,(*iter).second.total_bytes);
        printf("Tx    packets / bytes: %d / %d\n", (*iter).second.Tx_packets, (*iter).second.Tx_bytes);
        printf("Rx    packets / bytes: %d / %d\n", (*iter).second.Rx_packets, (*iter).second.Rx_bytes);
    }
    printf("=====================================================\n");
}
