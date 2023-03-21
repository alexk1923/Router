#include "queue.h"
#include "list.h"
#include "./include/skel.h"
#include <arpa/inet.h>
// #include <linux/ip.h>

#define MAX_RTABLE_ENTRIES 100000
#define MAX_ARP_ENTRIES 100
#define MAC_LENGTH 6

int compare_MAC(uint8_t *addr1, uint8_t *addr2) {
	for(int i = 0; i < MAC_LENGTH; i++) {
		if(addr1[i] != addr2[i]) {
			return 0;
		}
	}
	return 1;
}


int binary_search(struct route_table_entry* rtable, uint32_t searched_ip, int left, int right)

{
    if (left <= right) {
        int mid = left + (right - left) / 2;
        if ((searched_ip & rtable[mid].mask) == rtable[mid].prefix) {
			return mid;
		}
        
        if (ntohl(searched_ip & rtable[mid].mask) > ntohl(rtable[mid].prefix)) {
            return binary_search(rtable, searched_ip, mid + 1, right);
		}
		else {
        	return binary_search(rtable, searched_ip, left, mid - 1);
		}
    }
 
    return -1;
}


struct route_table_entry* LPM(uint32_t dest_ip, struct route_table_entry* rtable, int rtable_len) {

	int found = binary_search(rtable, dest_ip, 0, rtable_len - 1);
	if(found == -1) {
		return NULL;
	}
	return &rtable[found];
}


int search_dynamic_ip_ARP(struct arp_entry *arp_table, int arp_table_len, uint32_t ip, uint8_t *mac) {
	for(int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == ip) {
			memcpy(mac, &arp_table[i].mac, MAC_LENGTH);
			return 1;
		}
	}
	return 0;
}


void enque_pck(queue q, packet m) {
	packet *m_cpy = malloc(sizeof(packet));
	DIE(m_cpy == NULL, "memory");

	memcpy(m_cpy, &m, sizeof(m));

	queue_enq(q, m_cpy);
}



void add_arp_entry(struct arp_entry *arp_table, int *arp_table_len, struct arp_entry *arp_entry)  {

	for(int i = 0; i < *arp_table_len; i++) {
		/* If it already exists in the ARP Table */
		if(arp_table[i].ip == arp_entry->ip) {
			return;
		}
	}

	/* Add new entry */
	arp_table[*arp_table_len] = *arp_entry;
	(*arp_table_len)++;
}

void check_queue(queue q, struct arp_entry *arp_table, int arp_len,
struct route_table_entry *rtable, int rtable_len) {

	if(queue_empty(q)) {
		return;
	}

	/* Get first packet */
	packet *pck = (packet *)queue_peek(q);
	int found = 0;

	struct iphdr *ip_hdr = (struct iphdr *)(pck->payload + sizeof(struct ether_header));
	struct route_table_entry* LPM_route_entry = LPM(ip_hdr->daddr, rtable, rtable_len);


	for(int i = 0; i < arp_len; i++) {
		if(LPM_route_entry->next_hop == arp_table[i].ip) {
			/* Remove the packet from the queue */
			pck = (packet *)queue_deq(q);
			struct ether_header *eth_hdr = (struct ether_header *)pck->payload;

			/* Change packet info based on new MAC */
			uint8_t *router_mac = malloc(sizeof(MAC_LENGTH));
			get_interface_mac(LPM_route_entry->interface, router_mac);

			memcpy(eth_hdr->ether_shost, router_mac , MAC_LENGTH);
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, MAC_LENGTH);
			
			pck->interface = LPM_route_entry->interface;
			found = 1;
		}
	}

	if(found == 1) {
		send_packet(pck);
		return;
	} else {
		printf("No response for the first packet\n");
	}
	
}


void icmp_echo_send(packet m, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr, struct icmphdr new_icmp_hdr) {
	/* Make copy of original packet */
	packet *new_p = malloc(sizeof(packet));
	memcpy(new_p, &m, sizeof(packet));

	/* Extract headers */
	struct iphdr *ip_hdr = (struct iphdr *)(new_p->payload + sizeof(struct ether_header));
	struct ether_header *eth_hdr = (struct ether_header *) new_p->payload;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	/* Update Ethernet Header */
	memcpy(eth_hdr->ether_dhost, dest_mac, MAC_LENGTH);
	memcpy(eth_hdr->ether_shost, source_mac, MAC_LENGTH);

	/* Update IP Header */
	ip_hdr->daddr = ip_daddr;
	ip_hdr->saddr = ip_saddr;

	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	/* Update ICMP Header */
	memcpy(icmp_hdr, &new_icmp_hdr, sizeof(struct icmphdr));
	
	new_p->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	send_packet(new_p);
}


void icmp_err_send(packet m, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr, struct icmphdr new_icmp_hdr) {
	/* Make copy of original packet */
	packet *new_p = malloc(sizeof(packet));
	memcpy(new_p, &m, sizeof(packet));

	/* Extract headers */
	struct iphdr *ip_hdr = (struct iphdr *)(new_p->payload + sizeof(struct ether_header));
	struct ether_header *eth_hdr = (struct ether_header *) new_p->payload;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	/* Update Ethernet Header */
	memcpy(eth_hdr->ether_dhost, dest_mac, MAC_LENGTH);
	memcpy(eth_hdr->ether_shost, source_mac, MAC_LENGTH);

	/* Update IP Header */
	ip_hdr->daddr = ip_daddr;
	ip_hdr->saddr = ip_saddr;

	/* Copy the first 64 bytes above IP Header */
	void *after_ip = malloc(64);
	memcpy(after_ip, (new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr)), 64);
	
	/* Update IP Header */
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	/* Update ICMP Header */
	memcpy(icmp_hdr, &new_icmp_hdr, sizeof(struct icmphdr));

	/* Copy original 64 bytes */
	memcpy((new_p->payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)), after_ip, 64);
	
	new_p->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	send_packet(new_p);
}


void ip_checksumRFC1642(struct iphdr *ip_hdr) {

	u_int16_t old_checksum = ip_hdr->check;
	u_int16_t new_checksum = ~(~old_checksum + ~(ip_hdr->ttl + 1 ) + ip_hdr->ttl) - 1;

	ip_hdr->check = new_checksum;
}

/* Compare entries by mask, then by prefix */
int compare_entries (const void * a, const void * b) {
	struct route_table_entry a_entry = *(struct route_table_entry *)a;
	struct route_table_entry b_entry = *(struct route_table_entry *)b;
	int compare = (ntohl(a_entry.mask) - ntohl(b_entry.mask));
	if(compare != 0)
		return compare;
	else
		return (ntohl(a_entry.prefix) - ntohl(b_entry.prefix));
}


void arp_request(struct route_table_entry *LPM_router) {

	/* Create new ARP Packet */
	packet arp_packet;
	arp_packet.interface = LPM_router->interface;
	arp_packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	memset(arp_packet.payload, 0, 1600);

	/* Store broadcast address in a variable*/
	uint8_t *broadcast_addr = malloc(MAC_LENGTH);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);

	/* Generate Ethernet Header */
	struct ether_header* eth_hdr_arp = (struct ether_header *) arp_packet.payload;
	eth_hdr_arp->ether_type = ntohs(ETHERTYPE_ARP);
	get_interface_mac(LPM_router->interface, eth_hdr_arp->ether_shost);
	memcpy(eth_hdr_arp->ether_dhost, broadcast_addr, MAC_LENGTH);

	/* Generate ARP Header */
	struct arp_header* arp_hdr = (struct arp_header*) (arp_packet.payload + sizeof(struct ether_header));

	arp_hdr->op = htons(ARPOP_REQUEST);
	arp_hdr->ptype = htons(2048); /* aka 0x0800 */
	arp_hdr->plen = 4; 
	arp_hdr->htype = htons(1); /* Ethernet */
	arp_hdr->hlen = MAC_LENGTH;
	
	get_interface_mac(LPM_router->interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(LPM_router->interface));
	arp_hdr->tpa = LPM_router->next_hop;
	memcpy(arp_hdr->tha, broadcast_addr, MAC_LENGTH);
	
	send_packet(&arp_packet);
}

void arp_reply(packet m, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr) {

	memset(m.payload, 0, 1600);

	/* Modify Ethernet Header */
	struct ether_header* eth_hdr = (struct ether_header*) (m.payload);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	memcpy(eth_hdr->ether_shost, source_mac, MAC_LENGTH);
	memcpy(eth_hdr->ether_dhost, dest_mac, MAC_LENGTH);
	
	/* Modify ARP Header */
	struct arp_header* arp_hdr = (struct arp_header*) (m.payload + sizeof(struct ether_header));
	/* Modify ARP Header */
	arp_hdr->op = htons(ARPOP_REPLY); /* change request to reply code */
	arp_hdr->ptype = htons(2048); /* aka 0x0800 */
	arp_hdr->plen = 4; 
	arp_hdr->htype = htons(1); /* Ethernet */ 
	arp_hdr->hlen = 6;

	memcpy(arp_hdr->sha, source_mac, MAC_LENGTH);
	arp_hdr->spa = ip_saddr;
	
	memcpy(arp_hdr->tha, dest_mac, MAC_LENGTH);
	arp_hdr->tpa = ip_daddr;

	send_packet(&m);
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;
	setvbuf( stdout , NULL, _IONBF , 0);

	// Do not modify this line
	init(argc - 2, argv + 2);

	
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
	DIE(rtable == NULL, "memory");

	int rtable_len = read_rtable(argv[1], rtable);
	if(rtable_len <= 0) {
		printf("Reading error / empty route table\n");
	}

	/* Sort route table by masks and prefixes */
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_entries);

	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * MAX_ARP_ENTRIES);
	DIE(arp_table == NULL, "memory");

	/* Init size for empty ARP table */
	int arp_table_len = 0;

	queue q;
	q = queue_create();

	/* Define broadcast address */
	uint8_t *broadcast_addr = malloc(MAC_LENGTH);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		/**************** Forwarding ****************/
		struct ether_header *eth = (struct ether_header *) m.payload;


		/********* IPv4 Protocol *********/
		
		if(ntohs(eth->ether_type) == ETHERTYPE_IP) {
			printf("Protocol IPv4\n");
			uint8_t packet_interface_mac[MAC_LENGTH];
			get_interface_mac(m.interface, packet_interface_mac);

			/* L2 Validation */
			if(!compare_MAC(eth->ether_dhost, broadcast_addr) && !compare_MAC(eth->ether_dhost, packet_interface_mac)) {
				printf("Invalid L2\n");
				continue;
			}

			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			/* Checksum */
			if(ip_checksum((void *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("Wrong checksum\n");
				continue;
			}

			uint32_t interface_ip = inet_addr(get_interface_ip(m.interface));

			/* Check if ICMP echo request */
			if (ip_hdr->daddr == interface_ip) {
				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				
				if(icmp_hdr->type == ICMP_ECHO && icmp_hdr->code == 0) {
					uint8_t d_mac[MAC_LENGTH];
					memcpy(d_mac, eth_hdr->ether_dhost, MAC_LENGTH);

					/* create new ICMP Header */
					struct icmphdr new_icmp_hdr;
					memset(&icmp_hdr, 0, sizeof(struct icmphdr));
					new_icmp_hdr.code = 0;
					new_icmp_hdr.type = ICMP_ECHOREPLY;
					new_icmp_hdr.checksum = 0;
					new_icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

					icmp_echo_send(m, eth_hdr->ether_shost, d_mac, ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), new_icmp_hdr);
					continue;
				}
			}

			/* Check TTL */
			if(ip_hdr->ttl <= 1) {
				printf("Time exceeded:\n");

				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				
				uint8_t d_mac[MAC_LENGTH];
				memcpy(d_mac, eth_hdr->ether_dhost, MAC_LENGTH);

				/* create new ICMP Header */
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
				/* Update checksum */
				ip_checksumRFC1642(ip_hdr);
			}

			/* Search in route table */
			struct route_table_entry* LPM_router = LPM(ip_hdr->daddr, rtable, rtable_len);
			if (LPM_router == NULL) {
				printf("Destination unreachable\n");

				struct ether_header *eth_hdr = (struct ether_header *) m.payload;
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				
				/* create new ICMP Header */
				struct icmphdr icmp_hdr;
				memset(&icmp_hdr, 0, sizeof(struct icmphdr));
				icmp_hdr.code = 0;
				icmp_hdr.type = ICMP_DEST_UNREACH;
				icmp_hdr.checksum = 0;
				icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

				uint8_t d_mac[MAC_LENGTH];
				memcpy(d_mac, eth_hdr->ether_dhost, MAC_LENGTH);

				icmp_err_send(m, eth_hdr->ether_shost, d_mac, ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), icmp_hdr);
				continue;
			}

			/* Update L2 */
			uint8_t next_hop_mac[MAC_LENGTH];
			/* Check if next hop IP address exists in ARP Table */
			if(search_dynamic_ip_ARP(arp_table, arp_table_len, LPM_router->next_hop, next_hop_mac) == 1) {

			/* If it does, change Ethernet MAC source */
			get_interface_mac(LPM_router->interface, eth->ether_shost);
			memcpy(eth->ether_dhost, next_hop_mac, MAC_LENGTH);

			/* Update interface */
			m.interface = LPM_router->interface;

			send_packet(&m);
			continue;
			} else {
				/* If not, make an ARP request to find out the MAC
				 * Add the packet to the queue
				  */
				enque_pck(q, m);

				/* Make the request */
				arp_request(LPM_router);
				continue;
			}
		}

		/********* ARP Protocol *********/
		
		else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			printf("Protocol ARP\n");
			struct arp_header* arp_hdr = (struct arp_header*) (m.payload + sizeof(struct ether_header));

			/* If it is a reply */
			if(arp_hdr->op == htons(2)) {
				printf("ARP Reply\n");

				/* Add the new IP:MAC pair into the ARP table */
				struct arp_entry *arp_new_entry = malloc(sizeof(struct arp_entry));
				DIE(arp_new_entry == NULL, "memory");

				arp_new_entry->ip = arp_hdr->spa;
				memcpy(arp_new_entry->mac, arp_hdr->sha, MAC_LENGTH);
				add_arp_entry(arp_table, &arp_table_len, arp_new_entry);

				/* Check if the a saved packet can now be sent */
				check_queue(q, arp_table, arp_table_len, rtable, rtable_len);
				continue;
			}

			/* If it is a request */
			if(arp_hdr->op == htons(1)) {
				printf("ARP Request\n");
				
				/* Return interface MAC address */
				uint8_t found_MAC[MAC_LENGTH];
				get_interface_mac(m.interface, found_MAC);
				arp_reply(m, arp_hdr->sha, found_MAC , arp_hdr->spa, arp_hdr->tpa);
				continue;
			}
		
		}
		
	}
	free(arp_table);
	free(rtable);
}
