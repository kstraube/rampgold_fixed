#include "bee3_tester.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_ADDR (1024*1024*16/32)
#define QSIZE 1024

typedef struct {
	int head;
	int tail;
	uint32_t addr[QSIZE];
	uint32_t data[QSIZE*8];
} data_queue;

data_queue write_dq, read_dq;

enum write_state_type {IDLE, WRITE_1, WRITE_2, READ_1, READ_2};
typedef enum write_state_type write_state_t;
write_state_t write_state;

DPI_LINK_DECL DPI_DLLESPEC
void init_driver()
{
	memset(&write_dq, 0, sizeof(data_queue));
	memset(&read_dq, 0, sizeof(data_queue));
	write_state = IDLE;
}

static int read_count = 0;
uint32_t read_buf[8];

DPI_LINK_DECL DPI_DLLESPEC
void do_read(const read_data_type_in *rdata_in, read_data_type_out *rdata_out)
{	
	int ret, i;

	rdata_out->readRB = 0;

	if (rdata_in->RBempty == 0) {
		rdata_out->readRB = 1;
		read_buf[read_count++] = rdata_in->read_data1;
		read_buf[read_count++] = rdata_in->read_data2;
		read_buf[read_count++] = rdata_in->read_data3;
		read_buf[read_count++] = rdata_in->read_data4;
		if (read_count == 8) {
			read_count = 0;
			ret = memcmp(read_buf, &read_dq.data[read_dq.tail*8], 32);
			if (ret != 0) {
				printf("Error - memory mismatch at addr %08x\n", read_dq.addr[read_dq.tail]);
				printf("Data should be: ");
				for (i=0;i<8;i++)
					printf("%08x ",read_dq.data[(read_dq.tail*8)+i]);
				printf("\n is actually : ");
				for (i=0;i<8;i++)
					printf("%08x ",read_buf[i]);
				printf("\n");
			}
			else {
				printf("Memory matched at address %08x\n", read_dq.addr[read_dq.tail]);
			}
				
			read_dq.tail = (read_dq.tail + 1) % QSIZE;
		}
	}
}

static uint32_t last_addr = 0;
static uint32_t last_offset = 0;

DPI_LINK_DECL DPI_DLLESPEC
void do_write(const write_data_type_in* wdata_in, write_data_type_out* wdata_out)
{
	unsigned int i;
	uint32_t rand_addr, rand_offset, *data;

	wdata_out->writeWB = 0;
	wdata_out->writeAF = 0;
		
	switch(write_state) {
		case IDLE:
			
			if (wdata_in->reset == 0) {
				if (random() % 4 <= 2) {			// 75% chances stay in idle
					write_state = IDLE;
					break;
				}

				if (write_dq.tail == write_dq.head)
					write_state = WRITE_1;
				else 
				{
					if (random() % 2)
						write_state = WRITE_1;
					else
						write_state = READ_1;
				}
			}	
			break;
		case WRITE_1:
			if ((wdata_in->WBfull == 0) && (write_dq.tail != (write_dq.head + 1) % QSIZE)  && (wdata_in->AFfull == 0)) {
				wdata_out->read = 0;
				for (i=0;i<8;i++) 
					write_dq.data[(write_dq.head*8)+ i] = random();
				
				wdata_out->write_data1 = write_dq.data[(write_dq.head*8)];
				wdata_out->write_data2 = write_dq.data[(write_dq.head*8)+1];
				wdata_out->write_data3 = write_dq.data[(write_dq.head*8)+2];
				wdata_out->write_data4 = write_dq.data[(write_dq.head*8)+3];

				if (random() % 2) {
				  	rand_addr   = random() % MAX_ADDR;
				        rand_offset = (random() % 2) * 1024 * 1024 * 1024/32;
					write_dq.addr[write_dq.head] = rand_addr + rand_offset;
					last_addr   = rand_addr;
					last_offset = rand_offset;
				}
				else {
					write_dq.addr[write_dq.head] = ((last_addr+1) % MAX_ADDR) + last_offset;
					last_addr = (last_addr+1) % MAX_ADDR;
				}

				wdata_out->addr = write_dq.addr[write_dq.head];

				wdata_out->writeWB = 1;
				wdata_out->writeAF = 1;
				write_state = WRITE_2;
			} else
				write_state = IDLE;
			break;
		case WRITE_2:
			wdata_out->read = 0;
			
			wdata_out->write_data1 = write_dq.data[(write_dq.head*8)+4];
			wdata_out->write_data2 = write_dq.data[(write_dq.head*8)+5];
			wdata_out->write_data3 = write_dq.data[(write_dq.head*8)+6];
			wdata_out->write_data4 = write_dq.data[(write_dq.head*8)+7];

			wdata_out->addr = write_dq.addr[write_dq.head];
			wdata_out->writeWB = 1;
			wdata_out->writeAF = 1;

			printf("wrote data ");
			for (i=0;i<8;i++)
				printf("%08x ",write_dq.data[(write_dq.head*8)+i]);
			printf("to addr %08x\n",write_dq.addr[write_dq.head]); 

			write_dq.head = (write_dq.head+1) % QSIZE;

			if (random() % 16 < 2) {
				write_state = IDLE;
				break;
			}

			if (random() % 2) 
				write_state = WRITE_1;
			else
				write_state = READ_1; 
					
			break;
		case READ_1:
			if ((write_dq.tail != write_dq.head) && (read_dq.tail != (read_dq.head + 1) % QSIZE) && (wdata_in->AFfull == 0)) {
				wdata_out->read = 1;
				wdata_out->addr = write_dq.addr[write_dq.tail];
				wdata_out->writeAF = 1;
				wdata_out->writeWB = 0;
				write_state = READ_2;
			} else
				write_state = IDLE;
			break;
		case READ_2:
			wdata_out->read = 1;
			wdata_out->addr = write_dq.addr[write_dq.tail];
			wdata_out->writeAF = 1;
			wdata_out->writeWB = 0;		
			
			read_dq.addr[read_dq.head] = write_dq.addr[write_dq.tail];

			for (i=write_dq.tail; i != write_dq.head; i = (i+1) % QSIZE)
				if (write_dq.addr[i] == write_dq.addr[write_dq.tail])
					data = &write_dq.data[i*8];
				
			memcpy(&read_dq.data[read_dq.head*8], data, 32);

//			printf("Issued read request to addr %08x\n", write_dq.addr[write_dq.tail]);

			write_dq.tail = (write_dq.tail+1) % QSIZE;
			read_dq.head = (read_dq.head+1) % QSIZE;
			
			if (random() % 16 < 2) {
				write_state = IDLE;
				break;
			}

			if (random() % 2) 
				write_state = WRITE_1;
			else
				write_state = READ_1; 

			break;
		}
}


