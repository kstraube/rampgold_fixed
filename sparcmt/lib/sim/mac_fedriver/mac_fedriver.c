#include "mac_fedriver.h"
#include "socket.h"
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

// #define debug(...)
#define debug fprintf

int client_sock = -1;
int waiting = 0;

#define MAX_PACKET_SIZE 9000
#define CRCPOLY 0xEDB88320
#define INITXOR 0xFFFFFFFF
#define FINALXOR 0xFFFFFFFF


enum tx_state_type {TX_IDLE, START_TX, DATA_TX, TX_DONE};
typedef enum tx_state_type tx_state_t;
tx_state_t tx_state;

enum rx_state_type {RX_IDLE, DATA_RX, RX_DONE};
typedef enum rx_state_type rx_state_t;
rx_state_t rx_state;

DPI_LINK_DECL DPI_DLLESPEC
void init_driver()
{
  init_socket();
  tx_state = TX_IDLE;
  rx_state = RX_IDLE;
}

/**
 * Computes the CRC32 of the buffer of the given length
 */
int crc32(char *buffer, int length) {
    int i, j;
    uint32_t crcreg = INITXOR;
    
    for (j = 0; j < length; ++j) {
        unsigned char b = buffer[j];
        for (i = 0; i < 8; ++i) {
            if ((crcreg ^ b) & 1) {
                crcreg = (crcreg >> 1) ^ CRCPOLY;
            } else {
                crcreg >>= 1;
            }
            b >>= 1;
        }
    }

    return crcreg ^ FINALXOR;
}

int tx_count = 0;
uint8_t tx_buf[MAX_PACKET_SIZE];

DPI_LINK_DECL DPI_DLLESPEC
void transfer_tx(const tx_request_type *req)
{
	int ret;
	if (tx_state == TX_IDLE) 
	{
		if (req->tx_en == 1)
		{
			tx_state = DATA_TX;
			tx_buf[tx_count++] = req->tx_data;
		}
	}
	else if (tx_state == DATA_TX)
	{
		if (req->tx_en == 1)
		{
			if (tx_count >= 9000)
				debug(stderr,"tx_count >= 8500! something is wrong\n");
			else
				tx_buf[tx_count++] = req->tx_data;
		}
		else
			tx_state = TX_DONE;
	}
	else if (tx_state == TX_DONE)
	{
		if (client_sock == -1) 
			debug(stderr, "error trying to send response: client_sock == -1\n");
		else
			ret = write(client_sock, tx_buf+8, tx_count-12);
		waiting = 0;
		tx_count = 0;
		tx_state = TX_IDLE;
	}
}

int rx_count = 0;
char rx_buf[MAX_PACKET_SIZE];
int rx_length = 0;

const uint8_t preamble[] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xD5 };

DPI_LINK_DECL DPI_DLLESPEC
void transfer_rx(rx_response_type* resp)
{
	if (rx_state == RX_IDLE) 
	{
		if (!waiting)
		{
			int nbytes;
			client_sock = poll_socket(rx_buf+8, &nbytes);
			if (client_sock != -1)
			{
				memcpy(rx_buf, preamble, 8); // add preamble

				int minsz = 14+46; // 14 for header, 46 for min packet size
				if (nbytes < minsz)
				{
				    bzero(rx_buf+8+nbytes, (minsz-nbytes));
				    nbytes = minsz;
				}

				int crc = crc32(rx_buf+8, nbytes); // calculate CRC
				memcpy(rx_buf+nbytes+8, &crc, 4);

				rx_length = nbytes + 8 + 4; // preamble + CRC
				rx_count = 0;
				rx_state = DATA_RX;
				waiting = 1;
			}
		}
		resp->rxdv = 0;
		resp->rx_data = 0;
	}
	else if (rx_state == DATA_RX) 
	{
		resp->rxdv = 1;
		resp->rx_data = rx_buf[rx_count++];
		if (rx_count == rx_length) 
			rx_state = RX_IDLE;
	} 
}


