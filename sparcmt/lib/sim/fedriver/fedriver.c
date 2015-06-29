#include "fedriver.h"
#include "socket.h"
#include <stdio.h>

int previous_rw = 0;
int previous_addr = 0;
int request = 0;
int client_sock = -1;

#define debug(...)
//#define debug fprintf

DPI_LINK_DECL DPI_DLLESPEC
void init_driver()
{
  init_socket();
}

DPI_LINK_DECL DPI_DLLESPEC
void transfer(const response_type* rep, request_type* req)
{
  put_response(rep);
  get_request(req);
}

DPI_LINK_DECL DPI_DLLESPEC
void get_request(request_type* req)
{
  char msg[512];
  int nbytes;
  int i;

  client_sock = poll_socket(msg, &nbytes);

  if (client_sock != -1)
  {
    int cmd;
    int rw;
    unsigned int data[4];

    sscanf(msg, "%d", &cmd);

    debug(stderr, "cmd=%d msg=%s\n", cmd, msg);
    req->cmd = cmd;

    if (cmd == 1)
    {
      request = 1;
      debug(stderr, "(request) reset\n");
    }
    else if (cmd == 2)
    {
      sscanf(msg, "%d %d %u %u %u %u %u", &cmd, &rw, &req->addr, &data[3], &data[2], &data[1], &data[0]);

      for (i=0; i<8; i++)
      {
        req->rw[i] = rw&0x1;
        rw = rw >> 1;
      }

      req->data[0] = data[0]&0xffff;
      req->data[1] = (data[0]>>16)&0xffff;
      req->data[2] = data[1]&0xffff;
      req->data[3] = (data[1]>>16)&0xffff;
      req->data[4] = data[2]&0xffff;
      req->data[5] = (data[2]>>16)&0xffff;
      req->data[6] = data[3]&0xffff;
      req->data[7] = (data[3]>>16)&0xffff; previous_rw = rw;
      previous_addr = req->addr;
      request = 2;
      debug(stderr, "(request) rw=%d, addr=%08x, data=%08x\n", req->rw[0], req->addr, req->data[0]);
    }
  }
}

DPI_LINK_DECL DPI_DLLESPEC
void put_response(const response_type* rep)
{
  if (request == 1)
  {
    request = 0;
    debug(stderr, "(response) reset\n");
  }
  else if (request == 2)
  {
    int i;
    unsigned int data[4];
    char msg[512];

    data[0] = data[1] = data[2] = data[3] = 0;

    data[0] = ((rep->data[1]&0xffff)<<16) | (rep->data[0]&0xffff);
    data[1] = ((rep->data[3]&0xffff)<<16) | (rep->data[2]&0xffff);
    data[2] = ((rep->data[5]&0xffff)<<16) | (rep->data[4]&0xffff);
    data[3] = ((rep->data[7]&0xffff)<<16) | (rep->data[6]&0xffff);

    request = 0;
    debug(stderr, "(response) rw=%d, addr=%08x, data=%08x\n", previous_rw, previous_addr, rep->data[0]);

    sprintf(msg, "%u %u %u %u %u %u | %08x %08x %08x %08x %08x %08x",
      previous_rw, previous_addr, data[3], data[2], data[1], data[0], 
      previous_rw, previous_addr, data[3], data[2], data[1], data[0]);

    write(client_sock, msg, strlen(msg));
    client_sock = -1;
  }
}
