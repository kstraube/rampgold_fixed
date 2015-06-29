#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

int main(int argc, char** argv){
	char target_mac[6];
	char eth_device[256];
	char filename[256];
	char* buffer = (char*)malloc(ETH_FRAME_LEN);
	if(argc == 1) {
		target_mac[0] = 0x00;
		target_mac[1] = 0x24;
		target_mac[2] = 0x1d;
		target_mac[3] = 0x10;
		target_mac[4] = 0xa2;
		target_mac[5] = 0xb5;
		strcpy(eth_device, "eth0");
		strcpy(filename, "../../fs/i686/tests/e.y4m");
	}
	if(argc > 1) {
		assert(argc == 4);
		assert(strlen(argv[1]) == 17);
		sscanf(argv[1], "%2x:%2x:%2x:%2x:%2x:%2x", (unsigned int *)&target_mac[0],
		                                           (unsigned int *)&target_mac[1],
		                                           (unsigned int *)&target_mac[2],
		                                           (unsigned int *)&target_mac[3],
		                                           (unsigned int *)&target_mac[4],
		                                           (unsigned int *)&target_mac[5]);
		strcpy(eth_device, argv[2]);
		strcpy(filename, argv[3]);
		
	}
	pkt_rx p(target_mac, eth_device, filename);
	while(1){
		buffer = p.recv_pkt(); //received rx data (in 8 bit amount I think...)
		//need to copy buffer to the file after it has been accumulated properly to form a consistent packet
		}
	return 0;
}

void pkt_rx::pkt_rx(const char *target_mac, const char *eth_device, 
	                     const char *filename){
	seqno = 0;
	memcpy(this->target_mac, target_mac, 6);
	strcpy(this->eth_device, eth_device);
	strcpy(this->filename, filename);
	memset(&myaddr, 0, sizeof(myaddr));

	// setuid root to open a raw socket.  if we fail, too bad
	seteuid(0);
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	seteuid(getuid());
	if(sock < 0)
	  throw std::runtime_error("socket() failed! Maybe try running as root...");

	myaddr.sll_ifindex = if_nametoindex(eth_device);
	myaddr.sll_family = AF_PACKET;

	int ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
	if (ret < 0)
	  throw std::runtime_error("bind() failed!");

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(struct timeval)) < 0)
	  throw std::runtime_error("setsockopt() failed!");

	// get MAC address of local ethernet device
	struct ifreq ifr;
	strcpy(ifr.ifr_name, eth_device);
	ret = ioctl(sock, SIOCGIFHWADDR, (char *)&ifr);
	if (ret < 0)
	  throw std::runtime_error("ioctl() failed!");
}

char* pkt_rx::recv_pkt(Socket s){
	char* buffer = (char*)malloc(ETH_FRAME_LEN); /*Buffer for ethernet frame*/
	int length = 0; /*length of the received frame*/ 
	length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
	if (length == -1) { return ''; }
	return buffer;
}
