#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if_arp.h>
struct route_table_entry *routing_table;        //tabela de rutare
struct arp_table_entry arp_table[100];          //cache-ul ARP cu MAC-uri si IP-uri pe care il vom popula noi
int rtable_size, arp_table_size;                //dimensiunile lor
const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
queue arp_queue; 
int arp_queue_size;


void check_memory_allocation (void * buf) {
    if (buf == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
}

uint8_t* search_MAC_in_ARP_table(uint32_t ip_addr) {
     for (int i = 0; i < arp_table_size; ++i) {
        if (arp_table[i].ip == ip_addr) {
            return arp_table[i].mac;
        }
    }
    return NULL; // Adresa IP nu a fost găsită în tabela ARP
}

void parse_waiting_ARP() {

    if(!queue_empty(arp_queue)) {
        struct arp_waiting_packet* arp_pckt = queue_deq(arp_queue);
        struct ether_header *eth_hdr = (struct ether_header *) arp_pckt->packet; 

        uint32_t ip_target = arp_pckt->ip_target;
        uint8_t* found_MAC_addr = search_MAC_in_ARP_table(ip_target);
        if(found_MAC_addr) {
            //am gasit adresa in tabela ARP - rescrie L2 si trimite mai departe
            uint8_t src_MAC_addr[6];
            get_interface_mac(arp_pckt->port, src_MAC_addr);
            memcpy(eth_hdr->ether_shost, src_MAC_addr, sizeof(eth_hdr->ether_shost));
            memcpy(eth_hdr->ether_dhost, found_MAC_addr, sizeof(eth_hdr->ether_dhost));

            send_to_link(arp_pckt->port, arp_pckt->packet, arp_pckt->length);
            arp_queue_size --;
        }  
        else {
            printf("\tDid NOT find MAC in ARP table cache.\n");
            queue_enq(arp_queue,arp_pckt);
        }      
    }

    else{
        printf("\tARP waiting queue is empty\n");
    }
}

void enqueue_ARP_packet(char* packet, size_t len, int interface, uint32_t ip_target) {
    struct arp_waiting_packet* waiting_pckt = malloc(sizeof(struct arp_waiting_packet));
    check_memory_allocation(waiting_pckt);

    waiting_pckt->packet = malloc(len);
    memcpy(waiting_pckt->packet, packet, len);
    waiting_pckt->length = len;
    waiting_pckt->port = interface;
    waiting_pckt->ip_target = ip_target;
    queue_enq(arp_queue, waiting_pckt);
    ++arp_queue_size;

}

void respond_with_ARP_reply(int interface, uint8_t* dest_MAC, uint8_t* tha, uint32_t tpa) {
    //Raspunde printr-un ARP REPLY la un ARP REQUEST deja primit 

    uint32_t src_ip = inet_addr(get_interface_ip(interface));
    uint8_t src_MAC[6];
    get_interface_mac(interface,src_MAC);
    
    struct ARP_packet* packet = malloc(sizeof(struct ARP_packet)); //pachet ARP

    //Ethernet header
    packet->eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(packet->eth_hdr.ether_shost, src_MAC, 6);
    memcpy(packet->eth_hdr.ether_dhost, dest_MAC, 6);

    //ARP header
    packet->arp_hdr.htype = htons(ARPHRD_ETHER);
    packet->arp_hdr.ptype = htons(ETHERTYPE_IPv4); 
    packet->arp_hdr.hlen = 6;
    packet->arp_hdr.plen = 4;
    packet->arp_hdr.op = htons(ARPOP_REPLY);
    memcpy(packet->arp_hdr.sha, src_MAC, 6);
    packet->arp_hdr.spa = src_ip; 
    memcpy(packet->arp_hdr.tha, tha, 6);
    packet->arp_hdr.tpa = tpa;

    send_to_link(interface, (char *)packet, sizeof(struct ARP_packet));
}

void send_ARP_request(uint32_t unknown_ip_addr, int interface) {
    /*Antetul Ethernet: trebuie să conțină un ethertype care să identifice un pachet de tip ARP (0x806).
        Adresa MAC sursă va fi adresa interfeței routerului către next hop; adresa MAC destinație va fi
    cea de broadcast (FF:FF:FF:FF:FF:FF).
        Antetul ARP: trebuie să conțină tipul de adresă folosit în căutare (IPv4) împreună cu adresa în sine, precum 
    și tipul de adresă căutată (MAC) împreună cu adresa în sine*/
    
    struct ARP_packet* packet = malloc(sizeof(struct ARP_packet)); //pachet ARP
    
    //Ethernet header
    packet->eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    uint8_t src_mac[6];
    get_interface_mac(interface, src_mac);

    memcpy(packet->eth_hdr.ether_shost, src_mac, 6);
    memset(packet->eth_hdr.ether_dhost, 0xFF, 6);

    //ARP header
    packet->arp_hdr.htype = htons(ARPHRD_ETHER);
    packet->arp_hdr.ptype = htons(ETHERTYPE_IPv4);
    packet->arp_hdr.hlen = 6;
    packet->arp_hdr.plen = 4;
    packet->arp_hdr.op = htons(ARPOP_REQUEST);
    memcpy(packet->arp_hdr.sha, src_mac, 6);

    char *src_ip_str = get_interface_ip(interface);
    uint32_t src_ip = inet_addr(src_ip_str);    

    packet->arp_hdr.spa = src_ip; 
    memset(packet->arp_hdr.tha, 0x00, 6);
    packet->arp_hdr.tpa = unknown_ip_addr;

    send_to_link(interface, (char*) packet, sizeof(struct ARP_packet));
}

void update_arp_table(uint32_t ip_addr, uint8_t mac_addr[6]) {
    for (size_t i = 0; i < arp_table_size; ++i)
        if (arp_table[i].ip == ip_addr) {
            // Actualizează adresa MAC dacă adresa IP există deja în tabel
            memcpy(arp_table[i].mac, mac_addr, 6);
            return;
        }
    
    // Daca acea intrare nu exista, o adaugam in tabela ARP
    arp_table[arp_table_size].ip = ip_addr;
    memcpy(arp_table[arp_table_size].mac, mac_addr, 6);
    ++arp_table_size;
}

// Functie de comparare pentru qsort
int comparator(const void *a, const void *b) {
    const struct route_table_entry *entry1 = a;
    const struct route_table_entry *entry2 = b;

    // Sortam dupa prefix in ordine descrescatoare
    if (entry1->prefix != entry2->prefix)
        return (entry2->prefix - entry1->prefix);
    else
        return (entry2->mask - entry1->mask);
}

struct route_table_entry* search_route(uint32_t destination, int* port) {
    //port = interfata pe care vrei sa trimiti
    for(int i=0; i < rtable_size ; i++)
        if(routing_table[i].prefix == (destination & routing_table[i].mask)){
            (*port) = routing_table[i].interface;
            return (& routing_table[i]);
        }
    return NULL;
}

void send_ICMP_reply(char* org_pckt, size_t len, int interface) {
    /*Trimite un pachet ICMP de tipul "Echo reply"
    "Echo request" (type 8, code 0),  "Echo reply" (type 0, code 0)*/
    char *copy_pckt = malloc(len);
    check_memory_allocation(copy_pckt);
    memcpy(copy_pckt,org_pckt,len);
    size_t added = len - ETH_IP_ICMP_SIZE;

    uint8_t router_mac[6];
    uint32_t router_ip = inet_addr(get_interface_ip(interface));
    get_interface_mac(interface, router_mac);

    //Ethernet Header
    struct ether_header *eth_hdr = (struct ether_header *) copy_pckt;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, router_mac, 6);

    //IP Header
    struct iphdr *ip_hdr = (struct iphdr *)(copy_pckt + sizeof(struct ether_header));
    ip_hdr->ttl = 64;
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = router_ip;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + added);
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum ((uint16_t *) ip_hdr, sizeof(struct iphdr)));

    //ICMP Header
    struct icmphdr* icmp_hdr = (struct icmphdr *) (copy_pckt + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + added));

    /*Routerul trebuie să trimită înapoi și orice date care se aflau deasupra antetului ICMP în pachetul original.*/
    char *remains = malloc(added);
    check_memory_allocation(remains);
    memcpy(remains, copy_pckt + ETH_IP_ICMP_SIZE, added);

    copy_pckt = realloc(copy_pckt,ETH_IP_ICMP_SIZE + added);
    memcpy(copy_pckt +  ETH_IP_ICMP_SIZE, remains, added);

    send_to_link(interface, copy_pckt, ETH_IP_ICMP_SIZE + added);
}

void send_ICMP_error(char* org_pckt, uint8_t type, uint8_t code,  int interface) {
    //ERRORS - (type 3 , code 0) && (type 11, code 0)

    struct ether_header *src_eth_hdr = (struct ether_header *) org_pckt;
    struct iphdr *src_ip_hdr = (struct iphdr *)(org_pckt + sizeof(struct ether_header));
    
    char *packet = malloc(ETH_IP_ICMP_SIZE + ICMP_DATA_SIZE);
    // check_memory_allocation(packet);

    uint8_t router_mac[6];
    uint32_t router_ip = inet_addr(get_interface_ip(interface));
    get_interface_mac(interface, router_mac);

    //Ether Header
    struct ether_header* eth_hdr = (struct ether_header *) packet;
    memcpy(eth_hdr->ether_shost, router_mac, 6);
    memcpy(eth_hdr->ether_dhost, src_eth_hdr->ether_shost, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_IPv4);

    //IP Header
    struct iphdr* ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));
    memcpy(ip_hdr, src_ip_hdr, sizeof(struct iphdr));
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_DATA_SIZE);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = ICMP_PROTOCOL;
    ip_hdr->saddr = router_ip;
    ip_hdr->daddr = src_ip_hdr->saddr;
    ip_hdr->check = 0;
    ip_hdr->check = htons (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    //ICMP Header
    struct icmphdr* icmp_hdr = (struct icmphdr *) (packet + sizeof(struct ether_header)+ sizeof (struct iphdr));
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + ICMP_DATA_SIZE));

    /*Pachetul emis de router trebuie să conțină, 
    deasupra headerului ICMP, headerul de IPv4 al pachetului dropped, precum și 
    primii 64 de biți din payload-ul pachetului original (adică doar ce se află deasupra 
    antetului IPv4)*/

    memcpy(packet + ETH_IP_ICMP_SIZE, src_ip_hdr, ICMP_DATA_SIZE);
    send_to_link(interface, (char *)packet, ETH_IP_ICMP_SIZE + ICMP_DATA_SIZE);
}


int main(int argc, char *argv[])
{

	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
    arp_queue = queue_create();

    routing_table = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_TABLE_SIZE); 
    check_memory_allocation(routing_table);

    const char *path_rtable = argv[1];
    rtable_size = read_rtable(path_rtable, routing_table);
    if(rtable_size <= 0) {
        printf("Failed to populate routing table from file\n");
        exit(1);
    }

    //sortam tabela descrescator
    qsort(routing_table, rtable_size, sizeof(struct route_table_entry), comparator);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_links");
		struct ether_header *eth_hdr = (struct ether_header *) packet;
		/* Note that packets received are in network order,*/

        if (eth_hdr->ether_type == ntohs(ETHERTYPE_IPv4)) {
            //PACHET IP
            struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
           
            /* 1. Verifică dacă el este destinația*/
            uint8_t * mac_dest_address = eth_hdr->ether_dhost;
            int found_mac = 0; //boolean

            //i. Verificam adresele MAC ale interfetelor cu adresa MAC destinatie a pachetului

            //caz special - adresa de broadcast
            if(memcmp(mac_dest_address, broadcast_mac, 6) == 0 ){
                found_mac = 1;
            }
            else {
                //caz normal - adresa normala
                for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
                    uint8_t interface_mac[6];
                    get_interface_mac(i,interface_mac);
                    if(memcmp(interface_mac, mac_dest_address, 6) == 0)
                        //am gasit o interfata careia ii era destinat pachetul
                        found_mac = 1;
                }
            }

            if(!found_mac) {
                /*routerul nostru trebuie să considere doar pachetele trimise către el însuși*/
                printf("Drop packet with wrong MAC\n");
                continue;
            }

            uint32_t ip_dest_address = ip_hdr->daddr;
            //ii. comparam destinatia IP pachetului cu toate interfetele router-ului
            int stop_packet_processing = 0;
            for (int i=0; i < ROUTER_NUM_INTERFACES; i++) {
                char *interface_ip_str = get_interface_ip(i);
                uint32_t interface_ip = inet_addr(interface_ip_str);    //o converteste din char*

                if(ip_dest_address == interface_ip)
                    {
                        if(ip_hdr->ttl <= 1){
                            send_ICMP_error(packet, 11, 0, interface);
                            stop_packet_processing = 1;
                            break;
                        }
                        /*router-ul insusi este destinatarul pachetului*/
                        send_ICMP_reply(packet, len, interface);
                        stop_packet_processing = 1;
                        break;
                    }
            }
            if(stop_packet_processing)
                continue;

            /* 2. Verifică checksum */
            uint16_t sent_checksum = ntohs(ip_hdr->check);
            ip_hdr->check = 0;
            int checksum_OK = (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) == sent_checksum);
            if (!checksum_OK) {
                printf("Incorrect checksum. Drop packet\n");
                continue;
            }

            /*3. Verificare și actualizare TTL */
            if(ip_hdr->ttl <= 1) {
                //Routerul va trimite înapoi, către emițătorul pachetului un mesaj ICMP de tip "Time exceeded"
                send_ICMP_error(packet, 11, 0, interface);
                continue;
            }
            else ip_hdr->ttl--;


            /*4. Căutare în tabela de rutare */
            //O luam pe prima gasita (descrescator)
            int next_port; //se va salva in search_route
            struct route_table_entry* found_route = search_route(ip_hdr->daddr, &next_port);
            if(found_route == NULL) {
                /*În caz că nu găsește nimic, pachetul este aruncat. Routerul va trimite înapoi,
                către emițătorul pachetului un mesaj ICMP de tip "Destination unreachable" */
                printf("No match. Drop packet");
                send_ICMP_error(packet,3, 0, interface);
                continue;
            }

            /*5. Actualizare checksum */

            ip_hdr->check = 0; // setez checksum la 0 pentru recalculare
            ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
            

            //6. Rescriere adrese L2
            //ARP Protocol
            //1. Căutare în cache

            uint8_t* arp_found_mac = search_MAC_in_ARP_table(ip_dest_address);
            if(arp_found_mac){

                //  L-a gasit, deci rescrie antet L2 si forward
                uint8_t src_MAC_addr[6];
                get_interface_mac(next_port, src_MAC_addr);
                memcpy(eth_hdr->ether_shost, src_MAC_addr, sizeof(eth_hdr->ether_shost));
                memcpy(eth_hdr->ether_dhost, arp_found_mac, sizeof(eth_hdr->ether_dhost));

                send_to_link(next_port, packet , len); 
            }
            else {
                //Daca nu l-a gasit, il va salva in coada si va genera un ARP request pentru el.
                //Salvare pachet pentru mai târziu.
                enqueue_ARP_packet(packet,len, next_port, found_route->next_hop);

                //Generare ARP request
                send_ARP_request(ip_dest_address, next_port);

                continue;
            }
        }

        else 
        if(eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {

            struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));
            
            //Verificam daca e ARP REQUEST sau ARP REPLY
            if(ntohs(arp_hdr->op) == ARPOP_REQUEST) {
                //ARP REQUEST
                uint8_t router_MAC[6];
                get_interface_mac(interface, router_MAC);
                    respond_with_ARP_reply(interface, eth_hdr->ether_shost,arp_hdr->sha ,arp_hdr->spa);
                    continue;
                
            }

            else {
                if(ntohs(arp_hdr->op) == ARPOP_REPLY) {
                    //ARP REPLY
                    //Atunci când routerul primește un pachet de tip ARP reply, îl va adăuga în cache-ul ARP local. 
                    update_arp_table(arp_hdr->spa, arp_hdr->sha);

                    // În plus, routerul va parcurge lista de pachete care așteaptă răspunsuri ARP și le va trimite pe cele 
                    //pentru care adresa următorului hop este cunoscută.
                    parse_waiting_ARP();
                    continue;
                }

                else {
                    printf("\tUnknown ARP op. Drop\n");
                    continue;
                }
            }
        }
        else {
            printf("Ignored unknown type packet. Drop.\n");
            continue;
        }
    }
}