#ifndef __DMA_H
#define __DMA_H

#define LOADALT_OPCODE(asi)   (0xC0800000 | ((asi) << 5))
#define STOREALT_OPCODE(asi)  (0xC0A00000 | ((asi) << 5))

#define FLUSH_OPCODE	  0x81D82000
#define WRASR_OPCODE(rd)  (0x81800000 | (rd) << 25)

#define ACK_HEADER	  0xAAAA
#define NAK_HEADER	  0xBBBB

#ifdef __linux__
  #define MAX_PACKET_SIZE 9000
#else
  #define MAX_PACKET_SIZE 1500
#endif

enum packet_type {DATA_PACKET, COMMAND_PACKET, START_TM_PACKET, RESET_PACKET};

typedef struct { 
   uint16_t length;	// length of the payload of this packet
   uint16_t response_len;	// amount of data in the response packet we are requesting
   uint16_t pkt_type;	// packet type
} pkt_header_t;

// format of cmd for dma_command is:
// cmd[25:20] is threadid
// cmd[19:10] is ctrl_reg.buf_addr
// cmd[9:0] is ctrl_reg.count

typedef struct {
   uint32_t cmd;
   uint32_t  addr;
} dma_command_t;

typedef struct {
   uint8_t  threads_active;
   uint8_t  threads_total;
} dma_tm_control_t;


#endif /* __DMA_H */
