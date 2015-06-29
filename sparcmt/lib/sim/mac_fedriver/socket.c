#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

//#define PORT  (5556+getuid())
#define PORT 5556
#define MAXMSG  9000

#define debug(...)
//#define debug fprintf

static int server_sock;
static int count=0;
static fd_set active_fd_set, read_fd_set;

int init_socket(void)
{
  struct sockaddr_in servername;

  server_sock = socket(PF_INET, SOCK_STREAM, 0);

  if (server_sock < 0)
  {
    perror("socket");
    return -1;
  }

  servername.sin_family = AF_INET;
  servername.sin_port = htons(PORT);
  servername.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(server_sock, (struct sockaddr *)&servername, sizeof(servername)) < 0)
  {
    perror("bind");
    return -1;
  }

  if (listen(server_sock, 1) < 0)
  {
    perror("listen");
    return -1;
  }

  /* Initialize the set of active sockets.  */
  FD_ZERO(&active_fd_set);
  FD_SET(server_sock, &active_fd_set);

  debug(stderr, "init_socket! server_sock=%d\n", server_sock);

  return 0;
}

int poll_socket(char* msg, int* nbytes)
{
  struct timeval timeout;
  int nready;
  int client_sock;
  int sock = -1;

  count++;

  timeout.tv_sec = 0;
  timeout.tv_usec = 1;

  /* Block until input arrives on one or more active sockets.  */
  read_fd_set = active_fd_set;
  nready = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout);

  if (nready < 0)
  {
    perror("select");
    return -1;
  }

  for (client_sock=0; client_sock<FD_SETSIZE; client_sock++)
  {
    if (FD_ISSET(client_sock, &read_fd_set))
    {
      if (client_sock == server_sock)
      {
        struct sockaddr_in clientname;
        socklen_t size;

        size = sizeof(clientname);
        client_sock = accept(server_sock, (struct sockaddr *)&clientname, &size);
        debug(stderr, "count=%d server_sock=%d client_sock=%d\n", count, server_sock, client_sock);

        if (client_sock < 0)
        {
          perror("accept");
          return -1;
        }

        *nbytes = read(client_sock, msg, MAXMSG);
	if (*nbytes == -1)
		perror("read:");
        FD_SET(client_sock, &active_fd_set);
        sock = client_sock;
        break;
      }
      else
      {
        debug(stderr, "inside! client_sock=%d\n", client_sock);
        *nbytes = read(client_sock, msg, MAXMSG);

        if (*nbytes == 0)
        {
          FD_CLR(client_sock, &active_fd_set);
          close(client_sock);
        }
        else
        {
          sock = client_sock;
        }
        break;
      }
    }
  }
  return sock;
}
