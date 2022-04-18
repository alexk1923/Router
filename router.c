#include "queue.h"
#include "list.h"
#include "./include/skel.h"
#include <arpa/inet.h>
// #include <linux/ip.h>



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

void PRINT3(uint16_t addr) {
    int i;
    unsigned ipAddress = addr;
    unsigned char octet[2]  = {0,0};

    for (i=0; i<2; i++)
    {
        octet[i] = ( ipAddress >> (i*8) ) & 0xFF;
    }
    printf("%02x.%02x ",octet[0],octet[1]);    
	printf("\n");
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

	if(found == -1) {
		return NULL;
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
			printf("AM GASITTTTTT CV IN SEARCH DYNAMIC");
			memcpy(mac, &arp_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}

void print_arp_table(struct arp_entry *arp_table, int len) {

	printf("~~~~~~~~~Tabela ARP~~~~~~~~~~~~~~~~~~~\n");

	if(len == 0) {
		printf("Tabela ARP goala\n");
		return;
	}

	for(int i = 0; i < len; i++) {
		PRINT(arp_table[i].ip);
		printf("_");
		PRINT2(arp_table[i].mac);
	}
}


void enque_extended_pck(queue q, packet m) {
	// printf("AICII VRRRRRRRRRRRRRRR 1 ");
	packet *m_cpy = malloc(sizeof(packet));
	DIE(m_cpy == NULL, "memory");

	// memcpy(m_cpy, &m, sizeof(m));
	memmove(m_cpy, &m, sizeof(m));

	queue_enq(q, m_cpy);
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


void print_packet_info(packet p) {
	printf("*********Packet Info************\n");
	printf("Len: %d\n", p.len);
	printf("Interface: %d", p.interface);
	struct ether_header* eth_hdr = (struct ether_header *) p.payload;
	printf("Ethernet header:");
	print_eth_hdr(eth_hdr);
	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip_hdr = (struct iphdr *)(p.payload + sizeof(struct ether_header));
		printf("IP Source:");
		PRINT(ip_hdr->saddr);
		printf("IP Destination:");
		PRINT(ip_hdr->daddr);
		printf("ttl:%d\n", ip_hdr->ttl);
	} else {
		struct arp_header* arp_hdr = (struct arp_header*) (p.payload + sizeof(struct ether_header));
		print_arp_hdr(arp_hdr);
	}
	printf("*******************************\n");
}

void print_queue(queue q) {
	printf("Checking queue...\n");
	packet *pck = (packet *)queue_peek(q);
	printf("Primul packet:\n");
	print_packet_info(*pck);
	printf("\nEnd of checking queue\n");
}


void add_arp_entry(struct arp_entry *arp_table, int *arp_table_len, struct arp_entry *arp_entry)  {

	printf("New entry info:\n");
	PRINT(arp_entry->ip);
	PRINT2(arp_entry->mac);

	for(int i = 0; i < *arp_table_len; i++) {
		if(arp_table[i].ip == arp_entry->ip) { // era cu ntohl
			printf("Se mai gasi deja\n");
			return;
		}
	}

	
	arp_table[*arp_table_len] = *arp_entry;
	(*arp_table_len)++;
}

void check_queue(queue q, struct arp_entry *arp_table, int arp_len,
struct route_table_entry *rtable, int rtable_len) {

	
	if(queue_empty(q)) {
		return;
	}


	packet *pck = (packet *)queue_peek(q);
	int found = 0;

	struct iphdr *ip_hdr = (struct iphdr *)(pck->payload + sizeof(struct ether_header));

	struct route_table_entry* LPM_route_entry = LPM(ip_hdr->daddr, rtable, rtable_len);
	if (LPM_route_entry == NULL) {
		// TODO: trimite mesaj ICMP cu "Destination unreachable"
		return;
	}

	for(int i = 0; i < arp_len; i++) {
		if(LPM_route_entry->next_hop == arp_table[i].ip) {
			pck = (packet *)queue_deq(q);
			struct ether_header *eth_hdr;
			eth_hdr = (struct ether_header *)pck->payload;

			// rescriu adresa sursa ca fiind adresa MAC a interfetei routerului gasit din tabela
			uint8_t *router_mac = malloc(sizeof(ETH_ALEN));
			get_interface_mac(LPM_route_entry->interface, router_mac);

			printf("Mac-ul routerului:\n");
			PRINT2(router_mac);

			memcpy(eth_hdr->ether_shost, router_mac , 6);

			printf("Source host pentru ethernet inlocuit cu mac-ul routerului:\n");
			PRINT2(eth_hdr->ether_shost);

			// punem destinatia pentru pachet
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
			
			// updatam interfata ca sa fie trimis unde trebuie si tirmitem pachetul
			pck->interface = LPM_route_entry->interface;
			found = 1;
		}
	}

	printf("Primul pachet:\n");
	print_packet_info(*pck);

	if(found == 1) {
		printf("AM GASIT UN PACHET PE CARE IL VOM TRIMITE, CA AM PRIMIT RASPUNS\n");
		print_packet_info(*pck);
		send_packet(pck);
		return;
	} else {
		printf("Pentru primul pachet inca nu a venit raspunsul\n");
	}
	
}
void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}


void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};


	packet packet;
	void *payload;

	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));
	printf("Funfctie\n");
	PRINT3(icmp_hdr.checksum);


	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum((void *)&ip_hdr, sizeof(struct iphdr));


	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));
		printf("Funfctie2\n");
	PRINT3(icmp_hdr.checksum);

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	packet.interface = interface;

	send_packet(&packet);
}


void icmp_error(struct ether_header *eth_hdr,
				struct icmphdr *icmp_hdr,
				struct iphdr *ip_hdr,
				u_int8_t type,
				u_int8_t code,
				packet m)
{
	// Send back the packet
	uint32_t daddr = ip_hdr->saddr;
	uint32_t saddr = inet_addr(get_interface_ip(m.interface));

	// The mac source is my mac
	uint8_t *sha = eth_hdr->ether_dhost;
	uint8_t *dha = eth_hdr->ether_shost;

	int interface = m.interface;

	// Send an ICMP_REPLAY
	send_icmp_error(daddr, saddr, sha, dha, type, code, interface);
}


void icmp_echo_send(packet m, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr, struct icmphdr new_icmp_hdr) {
	packet *new_p = malloc(sizeof(packet));
	memcpy(new_p, &m, sizeof(packet));

	struct iphdr *ip_hdr = (struct iphdr *)(new_p->payload + sizeof(struct ether_header));
	struct ether_header *eth_hdr = (struct ether_header *) new_p->payload;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(eth_hdr->ether_dhost, dest_mac, 6);
	memcpy(eth_hdr->ether_shost, source_mac, 6);

	ip_hdr->daddr = ip_daddr;
	ip_hdr->saddr = ip_saddr;

	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	memcpy(icmp_hdr, &new_icmp_hdr, sizeof(struct icmphdr));
	
	new_p->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	send_packet(new_p);

}


void icmp_err_send(packet m, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr, struct icmphdr new_icmp_hdr) {
	packet *new_p = malloc(sizeof(packet));
	memcpy(new_p, &m, sizeof(packet));

	struct iphdr *ip_hdr = (struct iphdr *)(new_p->payload + sizeof(struct ether_header));
	struct ether_header *eth_hdr = (struct ether_header *) new_p->payload;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));


	memcpy(eth_hdr->ether_dhost, dest_mac, 6);
	memcpy(eth_hdr->ether_shost, source_mac, 6);

	ip_hdr->daddr = ip_daddr;
	ip_hdr->saddr = ip_saddr;


	void *after_ip = malloc(64);
	memcpy(after_ip, (new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr)), 64);
	
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	memcpy(icmp_hdr, &new_icmp_hdr, sizeof(struct icmphdr));
	memcpy((new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)), after_ip, 64);
	
	printf("AAAAAAAAAAAAAA MY CHECKSUM 2 AAAAAAAAAAAAAAAAA\n");
	new_p->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	send_packet(new_p);
}


void ip_checksumRFC1642(struct iphdr *ip_hdr) {

	printf("!!!!!!!!!!!!!!!!!!!!!!!RFC1642!!!!!!!!!!!!!!!");

	u_int16_t old_checksum = ip_hdr->check;
	u_int16_t new_checksum = ~(~old_checksum + ~(ip_hdr->ttl + 1 ) + ip_hdr->ttl) - 1;

	ip_hdr->check = new_checksum;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	setvbuf( stdout , NULL, _IONBF , 0);

	// Do not modify this line
	init(argc - 2, argv + 2);
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	DIE(rtable == NULL, "memory");

	int rtable_len = read_rtable(argv[1], rtable);

	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_len = parse_arp_table("./arp_table.txt", arp_table);
	DIE(arp_table == NULL, "memory");

	queue q;
	q = queue_create();

	uint8_t *broadcast_addr = malloc(ETH_ALEN);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */
		
		print_arp_table(arp_table, arp_table_len);

		print_packet_info(m);
		/**************** Forwarding ****************/

		/******** Extragem ethernet header ********/
		struct ether_header *eth = (struct ether_header *) m.payload;

		/********* Validare L2 ********/
		uint8_t packet_interface_mac[ETH_ALEN];
		get_interface_mac(m.interface, packet_interface_mac);

		printf("Mac interfetei pe care a fost trimis pachetul:\n");
		PRINT2(packet_interface_mac);


		if(!compare_MAC(eth->ether_dhost, broadcast_addr) && !compare_MAC(eth->ether_dhost, packet_interface_mac)) {
			printf("Invalid L2\n");
			continue;
		}

		/******** Daca e protocol IPv4 ********/
		if(ntohs(eth->ether_type) == ETHERTYPE_IP) {
			printf("Protocol IPv4\n");
			/******** Extragem IP header ********/
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// checksum
			if(ip_checksum((void *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("checksum gresit");
				continue;
			}

			uint32_t interface_ip = inet_addr(get_interface_ip(m.interface));

			// checl if ICMP echo request
			if (ip_hdr->daddr == interface_ip) {
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;


				if(icmp_hdr->type == ICMP_ECHO && icmp_hdr->code == 0) {
					uint8_t d_mac[ETH_ALEN];
					memcpy(d_mac, eth_hdr->ether_dhost, 6);

					struct icmphdr new_icmp_hdr;
					memset(&icmp_hdr, 0, sizeof(struct icmphdr));
					new_icmp_hdr.code = 0;
					new_icmp_hdr.type = ICMP_ECHOREPLY;
					new_icmp_hdr.checksum = 0;
					new_icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));
					// new_icmp_hdr.un.echo.id = icmp_hdr->un.echo.id;
					// new_icmp_hdr.un.echo.sequence = icmp_hdr->un.echo.sequence;

					icmp_echo_send(m, eth_hdr->ether_shost, d_mac, ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), new_icmp_hdr);
					continue;
				}
			}

			//ttl
			if(ip_hdr->ttl <= 1) {
				printf("TTL:%d\n", ip_hdr->ttl);
				// TODO: trimite mesaj ICMP cu time exceeded

				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;

				uint8_t d_mac[ETH_ALEN];
				memcpy(d_mac, eth_hdr->ether_dhost, 6);

				struct icmphdr icmp_hdr;
				memset(&icmp_hdr, 0, sizeof(struct icmphdr));
				icmp_hdr.code = 0;
				icmp_hdr.type = ICMP_TIME_EXCEEDED;
				icmp_hdr.checksum = 0;
				icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));
				 
				icmp_err_send(m, eth_hdr->ether_shost, d_mac, ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), icmp_hdr);
				continue;
			} else {
				ip_hdr->ttl--;
				ip_checksumRFC1642(ip_hdr);
			}

			/******** Cautare in tabela de rutare ********/
			struct route_table_entry* LPM_router = LPM(ip_hdr->daddr, rtable, rtable_len);
			if (LPM_router == NULL) {
				// TODO: trimite mesaj ICMP cu "Destination unreachable"
				printf("!!!!!!!!!!!!!!!!!! LPM ROUTER E NUL !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				// struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header));

				struct icmphdr icmp_hdr;
				memset(&icmp_hdr, 0, sizeof(struct icmphdr));
				icmp_hdr.code = 0;
				icmp_hdr.type = ICMP_DEST_UNREACH;
				icmp_hdr.checksum = 0;
				icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

				uint8_t d_mac[ETH_ALEN];
				memcpy(d_mac, eth_hdr->ether_dhost, 6);

				icmp_err_send(m, eth_hdr->ether_shost, d_mac, ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), icmp_hdr);
				continue;
			}

			printf("LPM Router: ");
			PRINT(LPM_router->next_hop);

			printf("Interfata LPM Router: ");
			printf("%d", LPM_router->interface);

			// /******** Actualizare checksum ********/
			// ip_hdr->check = 0;
			// ip_hdr->check = ip_checksum((void *) ip_hdr, sizeof(struct iphdr));

			/******** Rescriere L2 ********/

			// rescriu adresa destinatie ca fiind adresa MAC a next hope-ului routerului gasit in tabela
			uint8_t *next_hop_mac = malloc(sizeof(ETH_ALEN));
			// verific daca adresa ip a next hope-ului exista in ARP cache
			if(search_dynamic_ip_ARP(arp_table, arp_table_len, LPM_router->next_hop, next_hop_mac) == 1) {

			// rescriu adresa sursa ca fiind adresa MAC a interfetei routerului gasit din tabela
			uint8_t *router_mac = malloc(sizeof(ETH_ALEN));
			get_interface_mac(LPM_router->interface, router_mac);

			printf("Mac-ul routerului:\n");
			PRINT2(router_mac);

			memcpy(eth->ether_shost, router_mac , 6);

			printf("Source host pentru ethernet inlocuit cu mac-ul routerului:\n");
			PRINT2(eth->ether_shost);

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
				// daca intrarea nu exista
				printf("TREBUIE SA FAC UN REQUEST PT CA INTRAREA NU EXISTA");
				print_arp_table(arp_table, arp_table_len);
				enque_extended_pck(q, m);
				// TODO (In progress): generare pachet de tip ARP
				packet arp_packet;
				arp_packet.interface = LPM_router->interface;
				arp_packet.len = m.len;
				/**** 1. Generare antet Ethernet ****/
				struct ether_header* eth_hdr_arp = (struct ether_header *) arp_packet.payload;
				eth_hdr_arp->ether_type = ntohs(ETHERTYPE_ARP);
				// rescriu adresa sursa + destinatia pt antetul de Ethernet
				get_interface_mac(LPM_router->interface, eth_hdr_arp->ether_shost);
				memcpy(eth_hdr_arp->ether_dhost, broadcast_addr, 6);
		
				/**** 2. Generare antet ARP ****/
				struct arp_header* arp_hdr = (struct arp_header*) (arp_packet.payload + sizeof(struct ether_header));
				arp_hdr->op = htons(ARPOP_REQUEST); // 1 pt REQUEST
				arp_hdr->ptype = htons(2048); // aka 0x0800
				arp_hdr->plen = 4; // pt ca e adresa IPv*4*
				arp_hdr->htype = htons(1); // Ethernet 
				arp_hdr->hlen = 6; // Adresa MAC (xx:xx:xx:xx:xx:xx) -> 6 octeti
				// setam campurile pentru sursa
				get_interface_mac(LPM_router->interface, arp_hdr->sha);
				// TODO: DE CONVERTIT STRING IN ADRESA IP

				in_addr_t adresaIpSursa = inet_addr(get_interface_ip(LPM_router->interface));
				memcpy(&arp_hdr->spa, &adresaIpSursa, sizeof(uint32_t));
				// setam campurile pentru destinatie
				arp_hdr->tpa = LPM_router->next_hop;
				/*** In caz de request, nu stim adresa MAC a next hop, asta vrem sa aflam, deci ii punem broadcast ***/
				memcpy(arp_hdr->tha, broadcast_addr, 6);
				arp_packet.interface = LPM_router->interface;
				printf("Inainte sa trimitem pachetul de request, avem asa:\n");
				printf( "Interface: %d", arp_packet.interface);
				printf( "Len: %d", arp_packet.len);
				print_eth_hdr(eth_hdr_arp);
				print_arp_hdr(arp_hdr);
				printf("Trimit ARP REQUST");
				send_packet(&arp_packet);
				continue;
			}
		}

		// Daca e protocol ARP
		else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			printf("Protocol ARP\n");
			continue;
			// Adaugare ARP reply in cache-ul local
			/* Daca e un REPLY */
			struct arp_header* arp_hdr = (struct arp_header*) (m.payload + sizeof(struct ether_header));
			if(arp_hdr->op == htons(2)) {
				printf("++++++++Am primit un REPLY+++++++\n");

				/* Adaugare in cache (trebuie facut si in caz de reply, deoarece host-urile nu adauga implicit in cache	)*/
				struct arp_entry *arp_new_entry = malloc(sizeof(struct arp_entry));
				DIE(arp_new_entry == NULL, "memory");
				// Setam adresa IP a routerului care ne-a furnizat MAC-ul lui, datorita unei cereri anterioare
				arp_new_entry->ip = arp_hdr->spa;
				memcpy(arp_new_entry->mac, arp_hdr->sha, 6);

				add_arp_entry(arp_table, &arp_table_len, arp_new_entry);

				printf("Suntem in Reply, inainte sa verificam coada\n");

				print_arp_table(arp_table, arp_table_len);
				check_queue(q, arp_table, arp_table_len, rtable, rtable_len);
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
				
				/* Adaugare in cache */
				struct arp_entry *arp_new_entry = malloc(sizeof(struct arp_entry));
				DIE(arp_new_entry == NULL, "memory");
				// Setam adresa IP a routerului care ne-a furnizat MAC-ul lui, datorita unei cereri anterioare
				arp_new_entry->ip = arp_hdr->spa;
				memcpy(arp_new_entry->mac, arp_hdr->sha, 6);

				add_arp_entry(arp_table, &arp_table_len, arp_new_entry);
				
				send_packet(&m);
				continue;
			}
			
			
		}
		
	}
	free(arp_table);
	free(rtable);
}
