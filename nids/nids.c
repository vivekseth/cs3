#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/** Constants */

// ARP SPOOFING
u_char IP_1[4] = {'\xc0', '\xa8', '\x00', '\x64'};
u_char MAC_1[6] = {'\x7c', '\xd1', '\xc3', '\x94', '\x9e', '\xb8'};

u_char IP_2[4] = {'\xc0', '\xa8', '\x00', '\x67'};
u_char MAC_2[6] = {'\xd8', '\x96', '\x95', '\x01', '\xa5', '\xc9'};

u_char IP_3[4] = {'\xc0', '\xa8', '\x00', '\x01'};
u_char MAC_3[6] = {'\xf8', '\x1a', '\x67', '\xcd', '\x57', '\x6e'};

// PORT SCAN VICTIM
u_char IP_PORT_SCAN_VICTIM[4] = {'\xc0', '\xa8', '\x00', '\x65'};



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};


/** Port Set */
struct PortSet
{
	uint8_t table[8192];
	int count;
};

typedef struct PortSet PortSet;

PortSet *PortSet_create() {
	PortSet *set = calloc(1, sizeof(PortSet));
	return set;
}

void PortSet_destroy(PortSet *set) {
	free(set);
}

void PortSet_set(PortSet *set, int port) {
	int index = port / 8;
	int offset = port % 8;

	uint8_t orValue = 1 << offset;
	uint8_t currValue = set->table[index];
	uint8_t newValue = currValue | orValue;

	if (currValue != newValue) {
		set->count += 1;
	}

	set->table[index] = newValue;
}

/** IP Addr Hash Table */

struct IPAddrNode {
	void *value; // 2 bytes
	uint16_t tag; // 2 bytes
	struct IPAddrNode *next; // 4 or 8 bytes
};
typedef struct IPAddrNode IPAddrNode;
typedef IPAddrNode* IPAddrHashTable;
typedef void (*ValueDestroyer)(void *);

IPAddrHashTable *IPAddrHashTable_create() {
	IPAddrHashTable *table = calloc(65536, sizeof(IPAddrNode *));
	return table;
}

//PRIVATE
void IPAddrHashTable_destroy_row(IPAddrNode * row_head, ValueDestroyer valueDestroyer) {
	if (row_head == NULL) {
		return;
	}

	IPAddrNode * curr_node = row_head;
	IPAddrNode * next_node = row_head->next;

	while (next_node != NULL) {
		valueDestroyer(curr_node->value);
		free(curr_node);
		curr_node = next_node;
		next_node = next_node->next;
	}

	free(curr_node);
}

void IPAddrHashTable_destroy(IPAddrHashTable * table, ValueDestroyer vd) {
	int i;
	for (i=0; i<65536; i++) {
		IPAddrNode * row_head = table[i];
		IPAddrHashTable_destroy_row(row_head, vd);
		table[i] = NULL;
	}
	free(table);
}

//PRIVATE
void IPAddrHashTable_split_IP(u_char *ip_addr, int *out_key, int *out_tag) {
	int integerValue = *((int *)ip_addr);
	int key = integerValue >> 16;
	int tag = integerValue & 0x0000FFFF;

	*out_key = key;
	*out_tag = tag;
}

//PRIVATE
int IPAddrHashTable_find_node(IPAddrHashTable *table, u_char *ip_addr, IPAddrNode **out_node) {
	int key, tag;
	IPAddrHashTable_split_IP(ip_addr, &key, &tag);

	IPAddrNode *node = table[key];
	if (node == NULL) {
		return 1;
	}

	while(node->tag != tag) {
		node = node->next;
		if (node == NULL) {
			return 1;
		}
	}

	*out_node = node;
	return 0;
}

int IPAddrHashTable_read_value(IPAddrHashTable *table, u_char *ip_addr, void **out_value) {
	IPAddrNode *node;
	if (IPAddrHashTable_find_node(table, ip_addr, &node)) {
		return 1;
	}
	*out_value = node->value;
	return 0;
}

void IPAddrHashTable_set_value(IPAddrHashTable *table, u_char *ip_addr, void *value) {
	IPAddrNode *node;
	if (IPAddrHashTable_find_node(table, ip_addr, &node)) {
		node = malloc(sizeof(IPAddrNode));
		int key, tag;
		IPAddrHashTable_split_IP(ip_addr, &key, &tag);
		node->tag = tag;
		node->value = value;
		node->next = table[key];
		table[key] = node;
	} else {
		node->value = value;
	}
}

/** Utility */

void print_hex_memory(u_char *arr, int len) {
  int i;
  unsigned char *p = (unsigned char *)arr;
  for (i=0;i<len;i++) {
    printf("%02x:", p[i]);
  }
  printf("\n");
}

void print_int_memory(u_char *arr, int len) {
  int i;
  unsigned char *p = (unsigned char *)arr;
  for (i=0;i<len;i++) {
    printf("%02d.", p[i]);
  }
  printf("\n");
}

int compareMem(u_char *a1, u_char *a2, int len) {
	int i;
	for (i = 0; i < len; ++i) {
		if (a1[i] != a2[i]) {
			return 0;
		}
	}
	return 1;
}

/** PCAP Uility */

int filterPackets(char *filepath, char *filter_exp, pcap_handler callback, u_char *user) {
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Open the pcap file */
	handle = pcap_open_offline(filepath, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file (%s) : %s\n", filepath, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	pcap_loop(handle, 0, callback, user);
	
	/* And close the session */
	pcap_close(handle);
	return(0);
}

/** ARP Spoofing */

int validate(u_char *ipAddress, u_char *macAddress) {
	int i, j;
	if (compareMem(ipAddress, IP_1, 4)) {
		return compareMem(macAddress, MAC_1, 6);
	} else if (compareMem(ipAddress, IP_2, 4)) {
		return compareMem(macAddress, MAC_2, 6);
	} else if (compareMem(ipAddress, IP_3, 4)) {
		return compareMem(macAddress, MAC_3, 6);
	}
	return 0;
}

void ARPSpoofingCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	int *index = (int *)user;

	u_char *sourceHardwareAddress = (u_char *)packet + 22;
	u_char *sourceProtocolAddress = (u_char *)packet + 28;

	if (!validate(sourceProtocolAddress, sourceHardwareAddress)) {
		printf("ARP Spoof Attempt (packet index = %d)\n", *index);
		print_int_memory(sourceProtocolAddress, 4);
		print_hex_memory(sourceHardwareAddress, 6);
		printf("\n");
	}

	*index = *index + 1;
}

void detectARPSpoofingAttack(char *filepath) {
	int index = 0;
	filterPackets(filepath, "arp", ARPSpoofingCallback, (u_char *)&index);
}

/** Port Scan Attack */

void portScanAttackCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	IPAddrHashTable *table = (IPAddrHashTable *)user;

	struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	u_int size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if (ip->ip_p == IPPROTO_TCP) {
		struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		if (!(tcp->th_flags & TH_SYN)) {
			return;
		}
		printf("TCP SYN dest port %d\n", tcp->th_dport);


	} else if (ip->ip_p == IPPROTO_UDP) {
		struct sniff_udp *udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		printf("UDP dest port %d\n", udp->uh_dport);
	} else {
		return;
	}

	u_char *source = (u_char *)&(ip->ip_src);
	u_char *dest = (u_char *)&(ip->ip_dst);
	print_int_memory(source, 4);
	print_int_memory(dest, 4);


	printf("\n");
}

void detectPortScanAttack(char *filepath) {
	IPAddrHashTable *table = IPAddrHashTable_create();
	filterPackets(filepath, "", portScanAttackCallback, table);
}

/** Main */
int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Not enough arguments\n");
		return 1;
	}

	char *filepath = argv[1];
	detectPortScanAttack(filepath);

	// IPAddrHashTable *table = IPAddrHashTable_create();

	// int *d = malloc(sizeof(int));
	// *d = 1984;
	// IPAddrHashTable_set_value(table, IP_1, (void *)d);

	// *d = 6841;

	// void *value;
	// IPAddrHashTable_read_value(table, IP_1, &value);
	// int e = *((int *)value);

	// printf("%d\n", e);

	// IPAddrHashTable_destroy(table, free);

}



//65535