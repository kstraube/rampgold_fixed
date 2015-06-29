#include "memif_x86_dma.h"
#include "htif_x86_dma.h"
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <stdio.h>

#ifdef DEBUG_MODE
# define debug(...) printf(__VA_ARGS__)
#else
# define debug(...) do { } while(0)
#endif

memif_x86_dma_t::memif_x86_dma_t(htif_x86_dma_t* _htif, const char *_hw_addr, const char *_eth_device)
 : htif(_htif)
{
  seqno = 0;
  memcpy(ros_mac,_hw_addr,6);
  strcpy(eth_device, _eth_device);

  memset(&myaddr, 0, sizeof(myaddr));

  // setuid root to open a raw socket.  if we fail, too bad
  seteuid(0);
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  seteuid(getuid());
  if(sock < 0)
    throw std::runtime_error("socket() failed!");

  myaddr.sll_ifindex = if_nametoindex(eth_device);
  myaddr.sll_family = AF_PACKET;

  int ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0)
    throw std::runtime_error("bind() failed!");

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(struct timeval)) < 0)
    throw std::runtime_error("setsockopt() failed!");

  // get MAC address of local ethernet device
  struct ifreq ifr;
  strcpy(ifr.ifr_name, eth_device);
  ret = ioctl(sock, SIOCGIFHWADDR, (char *)&ifr);
  if (ret < 0)
    throw std::runtime_error("ioctl() failed!");
  memcpy(&appsvr_mac, &ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
}

memif_t::error memif_x86_dma_t::read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi)
{
  if(!htif->running)
    return memif_t::Invalid;

  x86_packet p(ros_mac,appsvr_mac,X86_CMD_LOAD,next_seqno(),0,addr,0);
  p.header.payload_size = htonl(len);
  for(int i=0; i<p.size(); i++) {
    debug("%02x ", (unsigned char)*((char *)&p + i));
  }
  debug("\n\n");
  send_packet(&p);
  if(p.size() - sizeof(x86_packet_header) != len)
    throw std::runtime_error("bad packet size");

  memcpy(bytes,p.payload,len);

  return memif_t::OK;
}

memif_t::error memif_x86_dma_t::write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi)
{
  if(!htif->running)
    return memif_t::Invalid;

  x86_packet p(ros_mac,appsvr_mac,X86_CMD_STORE,next_seqno(),len,addr,bytes);
  send_packet(&p);
  if(p.size() != sizeof(x86_packet_header))
    throw std::runtime_error("bad packet size");

  return memif_t::OK;
}

void memif_x86_dma_t::send_packet(x86_packet* packet)
{
  x86_packet response;

  for(int i = 0; i < 10; i++)
  {
    int ret = ::sendto(sock,(char*)packet,packet->size(),0,
                       (sockaddr*)&myaddr,sizeof(myaddr));
    if(ret != packet->size())
      continue;
    
    debug("wait for response \n");
    while(1)
    {
      ret = ::read(sock,(char*)&response,X86_MAX_PACKET_SIZE);
      if(ret == -1)
      {
        debug("timeout\n");
        break;
      }
      if(response.header.ethertype != htons(RAMP_ETHERTYPE) || memcmp(response.header.src_mac,packet->header.dst_mac,6) != 0)
        continue;
      else
	break;
    }
    if(ret == -1)
      continue;

    if(ntohl(response.header.payload_size) != ret-sizeof(response.header))
    {
      debug("packet size wrong\n");
      continue;
    }
    response.packet_size = ret;

    debug("got %d bytes: \n",ret);
    for(int i = 0; i < ret; i++)
      debug("%02x ",(unsigned int)(unsigned char)((char*)&response)[i]);
    debug("\n");

    // if we didn't send a broadcast packet, verify sender's mac
    if(response.header.cmd != X86_CMD_ACK) {
      debug("packet type wrong\n");
      continue;
   }
    if(response.header.seqno != packet->header.seqno) 
      continue;
    debug("got something good\n");

    *packet = response;
    return;
  }

  throw std::runtime_error("memif_sparc_dma_t::send_packet(): timeout");
}
