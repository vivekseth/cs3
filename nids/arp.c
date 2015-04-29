#include <pcap/pcap.h>
#include <stdio.h>

u_char IP_1[4] = {'\xc0', '\xa8', '\x00', '\x64'};
u_char MAC_1[6] = {'\x7c', '\xd1', '\xc3', '\x94', '\x9e', '\xb8'};

u_char IP_2[4] = {'\xc0', '\xa8', '\x00', '\x67'};
u_char MAC_2[6] = {'\xd8', '\x96', '\x95', '\x01', '\xa5', '\xc9'};

u_char IP_3[4] = {'\xc0', '\xa8', '\x00', '\x01'};
u_char MAC_3[6] = {'\xf8', '\x1a', '\x67', '\xcd', '\x57', '\x6e'};

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

int main(int argc, char *argv[]) {
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "arp or rarp";	/* The filter expression */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Open the pcap file */
	handle = pcap_open_offline("../traces/arpspoofing.pcap", errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file: %s\n", errbuf);
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
	
	/* Grab a packet */
	int packetNumber = 0;
	packet = pcap_next(handle, &header);
	while(packet) {
		u_char *sourceHardwareAddress = (u_char *)packet + 22;
		u_char *sourceProtocolAddress = (u_char *)packet + 28;

		if (!validate(sourceProtocolAddress, sourceHardwareAddress)) {
			printf("ARP Spoof Attempt (packet index = %d)\n", packetNumber);
			print_int_memory(sourceProtocolAddress, 4);
			print_hex_memory(sourceHardwareAddress, 6);
			printf("\n");
		}

		packet = pcap_next(handle, &header);
		packetNumber++;
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}
