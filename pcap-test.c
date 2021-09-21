#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "./my-headers.h"
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];	//param의 dev를 입력
	return true;
}

bool is_TCPIP(struct my_ethernet_hdr *eth_hdr, struct my_ipv4_hdr *ip_hdr) {
	if(ntohs(eth_hdr->ether_type)==ETHERTYPE_IP && ip_hdr->ip_p == IPTYPE_TCP)	return true;
	else return false;
}

void print_pkt(struct my_ethernet_hdr *eth_hdr, struct my_ipv4_hdr *ip_hdr, struct my_tcp_hdr *tcp_hdr, const u_char* packet){
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth_hdr->ether_shost[0],eth_hdr->ether_shost[1],eth_hdr->ether_shost[2],eth_hdr->ether_shost[3],eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]);
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth_hdr->ether_dhost[0],eth_hdr->ether_dhost[1],eth_hdr->ether_dhost[2],eth_hdr->ether_dhost[3],eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]);
	printf("src IP : %s\n",inet_ntoa(ip_hdr->ip_src));
	printf("dst IP : %s\n",inet_ntoa(ip_hdr->ip_dst));
	printf("src port : %d\n",ntohs(tcp_hdr->th_sport));
	printf("dst port : %d\n",ntohs(tcp_hdr->th_dport));

	uint16_t ip_hdr_len = (ip_hdr->ip_v_hl & 0xf) << 2;	//lower 4bit * 4
	uint16_t ip_dgram_len = ntohs(ip_hdr->ip_len);		
	uint16_t tcp_hdr_len = (tcp_hdr->th_off>>4) << 2;	//upper 4bit * 4
	uint16_t data_len = ip_dgram_len - (ip_hdr_len+tcp_hdr_len); //payload length

	printf("Data : ");
	if(data_len > 0){
		uint8_t *data = (uint8_t *)(packet + sizeof(struct my_ethernet_hdr) + ip_hdr_len + tcp_hdr_len);
		for (int i=0; i<=data_len&&i<8; i++){
			printf("0x%02x ",data[i]);
		}
	}
	else{
		printf("no data");
	}
	printf("\n");
}






int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);	//pcap을 여는 함수, (패킷을오픈할디바이스, 패킷최대크기, promiscuous, timeout, 에러버퍼)
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	
	struct my_ethernet_hdr *eth_hdr;
	struct my_ipv4_hdr *ip_hdr;
	struct my_tcp_hdr *tcp_hdr;
	

	while (true) {
		struct pcap_pkthdr* header;	//패킷 헤더를 담는 구조체
		const u_char* packet;		//패킷 데이터를 읽어올 위치
		int res = pcap_next_ex(pcap, &header, &packet);	//pcap에서 데이터를 읽어 header에 패킷헤더를 저장하고 packet가 패킷 데이터를 가르키도록 함
		if (res == 0) continue;	//timeout
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {	//에러 발생시 예외처리
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		eth_hdr = (struct my_ethernet_hdr *) (packet);
		ip_hdr = (struct my_ipv4_hdr *)(packet + sizeof(struct my_ethernet_hdr));
		tcp_hdr = (struct my_tcp_hdr *) (packet + sizeof(struct my_ipv4_hdr) + sizeof(struct my_ethernet_hdr));

		if(!is_TCPIP(eth_hdr,ip_hdr))	continue;
		//printf("%d bytes caputred\n",header->caplen);
		print_pkt(eth_hdr,ip_hdr,tcp_hdr,packet);
		printf("\n");
	}

	pcap_close(pcap);	//패킷을 닫는다.
}
