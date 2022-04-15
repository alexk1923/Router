#include "queue.h"
#include "./include/skel.h"
#include <arpa/inet.h>
//#include <linux/ip.h>



void PRINT(uint32_t addr) {
    int i;
    unsigned int  ipAddress = addr;
    unsigned char octet[4]  = {0,0,0,0};

    for (i=0; i<4; i++)
    {
        octet[i] = ( ipAddress >> (i*8) ) & 0xFF;
    }
    printf("%d.%d.%d.%d ",octet[0],octet[1],octet[2],octet[3]);    
	printf("\n");
}


void PRINT2(uint8_t *addr) {
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    addr[0] & 0xff,  addr[1] & 0xff,  addr[2] & 0xff,
    addr[3] & 0xff,  addr[4] & 0xff,  addr[5] & 0xff);
}

int compare_MAC(uint8_t *addr1, uint8_t *addr2) {
	for(int i = 0; i < 6; i++) {
		if(addr1[i] != addr2[i]) {
			return 0;
		}
	}
	return 1;
}

struct route_table_entry* LPM(uint32_t dest_ip, struct route_table_entry* rtable, int rtable_len) {
	int found = -1;
	int max_mask = 0;
	for(int i = 0; i < rtable_len; i++) {
		if((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			if(ntohl(rtable[i].mask) > ntohl(max_mask)) {
				max_mask = rtable[i].mask;
				found = i;
			}
		}
	}
	printf("Pentru adresa destinatie IP: ");
	PRINT(dest_ip);
	printf("\nAplicand masca, rezulta:");
	PRINT((dest_ip & rtable[found].mask));

	printf("\n a fost egala cu prefixul:");
	PRINT(rtable[found].prefix);
	printf("****END OF LPM*******");
	return &rtable[found];
}

void get_mac_ip(uint32_t ip, uint8_t *mac)
{
	
}

void search_ip_ARP(struct arp_entry *arp_table, uint32_t ip, uint8_t *mac){
	printf("S-a parsat ARP Table\n");
	parse_arp_table("./arp_table.txt", arp_table);
	for(int i = 0; i < 10; i++) {
		if(arp_table[i].ip == ip) {
			memcpy(mac, arp_table[i].mac, 6);
		}
	}
}

int search_dynamic_ip_ARP(struct arp_entry *arp_table, int arp_table_len, uint32_t ip, uint8_t *mac) {
	for(int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == ip) {
			// PRINT2(arp_table[i].mac);
			printf("2");
			memcpy(mac, arp_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}

void print_arp_table(struct arp_entry *arp_table, int len) {

	if(len == 0) {
		printf("Tabela ARP goala\n");
		return;
	}

	for(int i = 0; i < len; i++) {
		PRINT(arp_table->ip);
		printf(" ");
		PRINT2(arp_table->mac);
	}
}

void check_queue(queue q, struct arp_entry *arp_table, int len) {

	
	if(queue_empty(q)) {
		return;
	}


	extended_packet *ext_pck = (extended_packet *)queue_peek(q);
	int found = 0;



	for(int i = 0; i < len; i++) {
		if(ext_pck->LPM_route_entry->next_hop == arp_table[i].ip) {
			ext_pck = (extended_packet *)queue_deq(q);
			struct ether_header *eth_hdr;
			eth_hdr = (struct ether_header *)(*ext_pck->pck).payload;

			// punem destinatia pentru pachet
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
			
			// updatam interfata ca sa fie trimis unde trebuie si tirmitem pachetul
			ext_pck->pck->interface = ext_pck->LPM_route_entry->interface;
			found = 1;
		}
	}

	if(found == 1) {
		printf("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
		send_packet(ext_pck->pck);
	} else {
		printf("Pentru primul pachet inca nu a venit raspunsul\n");
	}
	
}

void enque_extended_pck(queue q, packet m, struct route_table_entry *LPM_route_entry) {
	// printf("AICII VRRRRRRRRRRRRRRR 1 ");
	packet *m_cpy = malloc(sizeof(packet));
	DIE(m_cpy == NULL, "memory");

	memcpy(m_cpy, &m, sizeof(m));
	
	extended_packet *ext_pck = malloc(sizeof(extended_packet));
	DIE(ext_pck == NULL, "memory");
	ext_pck->pck = m_cpy;
	// printf("AICIIIIIIIIIIIA VRRRRRRRRRRRRRRRRR 2");
	struct route_table_entry *LPM_route_entry_cpy = malloc(sizeof(struct route_table_entry));
	memcpy(LPM_route_entry_cpy, LPM_route_entry, sizeof(struct route_table_entry));
	ext_pck->LPM_route_entry = LPM_route_entry_cpy;

	queue_enq(q, ext_pck);
}


void print_arp_hdr(struct arp_header* arp_hdr) {
 	printf("Op:%d\n", arp_hdr->op);
	printf("Source IP + MAC:\n");
	PRINT(arp_hdr->spa);
	printf(" ");
	PRINT2(arp_hdr->sha);
	printf("Target IP + MAC:\n");
	PRINT(arp_hdr->tpa);
	printf(" ");
	PRINT2(arp_hdr->tha);
	printf("\n");
}

void print_eth_hdr(struct ether_header *eth) {
	printf("Ethernet Dest: ");
	PRINT2(eth->ether_dhost);
	printf("\nEthernet Source: ");
	PRINT2(eth->ether_shost);
	printf("\n");
}


void add_arp_entry(struct arp_entry *arp_table, int *arp_table_len, struct arp_entry *arp_entry)  {



	for(int i = 0; i < *arp_table_len; i++) {
		if(arp_table[i].ip == arp_entry->ip) {
			return;
		}
	}
	arp_table[*arp_table_len] = *arp_entry;
	(*arp_table_len)++;
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;
	

	// Do not modify this line
	init(argc - 2, argv + 2);
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 800000);
	DIE(rtable == NULL, "memory");

	int rtable_len = read_rtable(argv[1], rtable);

	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 80000);
	DIE(arp_table == NULL, "memory");
	int arp_table_len = 0;

	queue q;
	q = queue_create();


	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */
		
		printf("argv[1]:%s\n", argv[1]);

		printf("---------------INCEPUT PACHET-----------------\n");
		printf("Interfata: %d\n", m.interface);
		printf("Lungime pachet: %d\n", m.len);
		/**************** Forwarding ****************/

		/******** Extragem ethernet header ********/
		struct ether_header *eth = (struct ether_header *) m.payload;


		/********* Validare L2 ********/
		uint8_t *broadcast_addr = malloc(ETH_ALEN);
		hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);

		// printf("Adresa de broadcast:\n");
		// PRINT2(broadcast_addr);

		uint8_t packet_interface_mac[ETH_ALEN];

		get_interface_mac(m.interface, packet_interface_mac);
		printf("Mac interfetei pe care a fost trimis pachetul:\n");
		PRINT2(packet_interface_mac);

		printf("MAC-ul sursa de pe ethernet:\n");
		PRINT2(eth->ether_shost);

		printf("MAC-ul destinatie de pe ethernet:\n");
		PRINT2(eth->ether_dhost);


		if(!compare_MAC(eth->ether_dhost, broadcast_addr) && !compare_MAC(eth->ether_dhost, packet_interface_mac)) {
			printf("Invalid L2\n");
			continue;
		}

		printf("Ether type: %02x", eth->ether_type);
		/******** Daca e protocol IPv4 ********/
		if(ntohs(eth->ether_type) == ETHERTYPE_IP) {
			printf("Protocol IPv4\n");


			/******** Extragem IP header ********/
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			printf("IP Source:");
			PRINT(ip_hdr->saddr);

			printf("IP Destination:");
			PRINT(ip_hdr->daddr);


			if(ip_checksum((void *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("checksum gresit");
				continue;
			}

			if(ip_hdr->ttl < 1) {
				printf("TTL:%d\n", ip_hdr->ttl);
				// TODO: trimite mesaj ICMP cu time exceeded
				struct icmphdr* icmp_hdr = malloc(sizeof(struct icmphdr));
				// Time exceeded
				icmp_hdr->type = 11;
				icmp_hdr->code = 0;
				continue;
				
			} else {
				ip_hdr->ttl--;
			}

			/******** Cautare in tabela de rutare ********/

			struct route_table_entry* LPM_router = LPM(ip_hdr->daddr, rtable, rtable_len);
			if (LPM_router == NULL) {
				// TODO: trimite mesaj ICMP cu "Destination unreachable"
				continue;
			}
			printf("LPM Router: ");
			PRINT(LPM_router->next_hop);

			printf("Interfata LPM Router: ");
			printf("%d", LPM_router->interface);

			/******** Actualizare checksum ********/
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((void *) ip_hdr, sizeof(struct iphdr));

			/******** Rescriere L2 ********/


			// rescriu adresa sursa ca fiind adresa MAC a routerului gasit din tabela
			uint8_t *router_mac = malloc(sizeof(ETH_ALEN));
			get_interface_mac(LPM_router->interface, router_mac);

			printf("Mac-ul routerului:\n");
			PRINT2(router_mac);

			memcpy(eth->ether_shost, router_mac , 6);

			printf("Source host pentru ethernet inlocuit cu mac-ul routerului:\n");
			PRINT2(eth->ether_shost);

			// rescriu adresa destinatie ca fiind adresa MAC a next hope-ului routerului gasit in tabela
			uint8_t *next_hop_mac = malloc(sizeof(ETH_ALEN));
			// next_hop_mac = NULL;
			// verific daca adresa ip a next hope-ului exista in ARP cache
			

			if(search_dynamic_ip_ARP(arp_table, arp_table_len, LPM_router->next_hop, next_hop_mac) == 1) {
				// daca exista
				printf("Adresa IP exista in cache ARP\n");
				printf("Mac-ul next hop-ului:\n");
				PRINT2(next_hop_mac);

				// inlocuim destinatia din Ethernet
				memcpy(eth->ether_dhost, next_hop_mac, 6);

				printf("Destination host pentru ethernet inlocuit cu mac-ul next hope-ului:\n");
				PRINT2(eth->ether_dhost);

				m.interface = LPM_router->interface;
				send_packet(&m);
				continue;
			} else {
				printf("TREBUIE SA FAC UN REQUEST PT CA INTRAREA NU EXISTA");
				print_arp_table(arp_table, arp_table_len);
				// daca intrarea nu exista
				enque_extended_pck(q, m, LPM_router);
				// TODO (In progress): generare pachet de tip ARP
				packet arp_packet;

				arp_packet.interface = m.interface;
				arp_packet.len = m.len;
				printf("AICIIIIIIIIIIIA");
				/**** 1. Generare antet Ethernet ****/
				struct ether_header* eth_hdr_arp = (struct ether_header *) arp_packet.payload;
				eth_hdr_arp->ether_type = ntohs(ETHERTYPE_ARP);

				// rescriu adresa sursa pt antetul de Ethernet
				get_interface_mac(m.interface, eth_hdr_arp->ether_shost);
				//memcpy(eth_hdr_arp->ether_shost, eth->ether_shost, 6);


				// rescriu adresa destinatie pt antetul de Ethernet
				memcpy(eth_hdr_arp->ether_dhost, broadcast_addr, 6);
		
				/**** 2. Generare antet ARP ****/
				struct arp_header* arp_hdr = (struct arp_header*) (arp_packet.payload + sizeof(struct ether_header));

				arp_hdr->op = htons(1); // 1 pt REQUEST
				arp_hdr->ptype = htons(2048); // aka 0x0800
				arp_hdr->plen = 4; // pt ca e adresa IPv*4*
				arp_hdr->htype = htons(1); // Ethernet 
				arp_hdr->hlen = 6; // Adresa MAC (xx:xx:xx:xx:xx:xx) -> 6 octeti
				// setam campurile pentru sursa
				get_interface_mac(LPM_router->interface, arp_hdr->sha);
				// TODO: DE CONVERTIT STRING IN ADRESA IP

				/* struct in_addr *ip_adr_source = malloc(sizeof(struct in_addr));
				 * ip_adr_source->s_addr = inet_addr(get_interface_ip(m.interface));
				 */


				//inet_aton(get_interface_ip(m.interface))
				//arp_hdr->spa = ip_hdr->saddr;
				in_addr_t adresaIpSursa = inet_addr(get_interface_ip(LPM_router->interface));
				memcpy(&arp_hdr->spa, &adresaIpSursa, sizeof(uint32_t));
				//arp_hdr->spa = inet_addr(get_interface_ip(m.interface));	
				// setam campurile pentru destinatie
				arp_hdr->tpa = LPM_router->next_hop;
				/*** In caz de request, nu stim adresa MAC a next hop, asta vrem sa aflam, deci ii punem broadcast ***/
				memcpy(arp_hdr->tha, broadcast_addr, 6);
				printf("AICIIIIIIIIIIIA4");
				arp_packet.interface = LPM_router->interface;
				printf("Inainte sa trimitem pachetul de request, avem asa:\n");
				printf( "Interface: %d", arp_packet.interface);
				printf( "Len: %d", arp_packet.len);
				print_eth_hdr(eth_hdr_arp);
				print_arp_hdr(arp_hdr);

				send_packet(&arp_packet);
				continue;
			}

			// get_ip_mac(LPM_router->next_hop, next_hop_mac);

			// printf("Mac-ul next hop-ului:\n");
			// PRINT2(next_hop_mac);

			// memcpy(eth->ether_dhost, next_hop_mac, 6);

			// printf("Destination host pentru ethernet inlocuit cu mac-ul next hope-ului:\n");
			// PRINT2(eth->ether_dhost);

		}

		// Daca e protocol ARP
		else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			printf("Protocol ARP\n");

			// Adaugare ARP reply in cache-ul local
			/* Daca e un REPLY */
			struct arp_header* arp_hdr = (struct arp_header*) (m.payload + sizeof(struct ether_header));
			if(arp_hdr->op == htons(2)) {
				printf("++++++++Am primit un REPLY+++++++\n");
				struct arp_entry *arp_new_entry = malloc(sizeof(struct arp_entry));
				DIE(arp_new_entry == NULL, "memory");
				// Setam adresa IP a routerului care ne-a furnizat MAC-ul lui, datorita unei cereri anterioare
				arp_new_entry->ip = arp_hdr->spa;
				memcpy(arp_new_entry->mac, arp_hdr->sha, 6);

				add_arp_entry(arp_table, &arp_table_len, arp_new_entry);

				printf("Suntem in Reply, inainte sa verificam coada\n");
				print_arp_table(arp_table, arp_table_len);
				check_queue(q, arp_table, arp_table_len);
				continue;
			}


			/* Daca e un REQUEST */
			if(arp_hdr->op == htons(1)) {
				printf("++++++++Am primit un REQUEST+++++++\n");
				printf("Inainte de schimbari pt source:\n");
				print_arp_hdr(arp_hdr);
				
				// trebuie sa ii returnez adresa MAC
				arp_hdr->op = htons(2);
				// copii pentru adresele sursa
				uint8_t sha_cpy[ETH_ALEN];
				memcpy(sha_cpy, arp_hdr->sha, 6);
				uint32_t spa_cpy = arp_hdr->spa;


				// updatam pentru urmatorul pas (schimbam adresele sursa)
				// punem in SHA adresa MAC pe care doream sa o aflam

				get_interface_mac(m.interface, arp_hdr->sha);
				arp_hdr->spa = arp_hdr->tpa;

				// updatam pentru urmatorul pas (schimbam adresele destinatie)
				memcpy(arp_hdr->tha, sha_cpy, 6);
				arp_hdr->tpa = spa_cpy;

				// NU uitam sa updatam si Ethernet Header
				struct ether_header* eth_hdr = (struct ether_header *) m.payload;
				eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
				// setam adresa MAC a sursei (locul in care ne aflam in acest moment)
				memcpy(eth_hdr->ether_shost, arp_hdr->sha, 6);
				// setam adresa MAC a destinatiei unde vom trimite pachetul (acolo de unde am primti REQUEST)
				memcpy(eth_hdr->ether_dhost, sha_cpy, 6);


				printf("Am primit un REQUEST, iar asta e structura pachetului inainte sa trimitem REPLY\n");
				print_eth_hdr(eth_hdr);
				print_arp_hdr(arp_hdr);
				
				send_packet(&m);
				continue;
			}
			
			
		}
	}
}
