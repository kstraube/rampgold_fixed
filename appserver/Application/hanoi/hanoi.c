#include <Common/itoa.h>
#include <stdlib.h>
#include <string.h>

int hanoi_recur(int ndisks, int from, int to, int using)
{
  int moves = 0;

  if(ndisks)
  {
    char buf[64] = "move ";

    moves = 1 + hanoi_recur(ndisks-1,from,using,to);

    itoa(from,buf+strlen(buf),10);
    strcat(buf," --> ");
    itoa(to,buf+strlen(buf),10);
    strcat(buf,"\n");
    write(1,buf,strlen(buf));

    moves += hanoi_recur(ndisks-1,using,to,from);
  }

  return moves;
}

int hanoi(int ndisks)
{
  return hanoi_recur(ndisks,1,3,2);
}

int main()
{
  int N = 10, moves;
  char buf[64] = "number of moves: ";

  moves = hanoi(N);

  itoa(moves,buf+strlen(buf),10);
  strcat(buf,"\n");
  write(1,buf,strlen(buf));

  return 0;
}

