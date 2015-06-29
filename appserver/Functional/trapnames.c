#include "traps.h"
#include <string.h>
#include <stdio.h>


const char* get_trap_name(int trap)
{
  static char trap_names[NUM_TRAPS][64];
  static int init = 0;
  if(!init)
  {
    init = 1;

    int i;
    for(i = 0; i < 256; i++)
    {
      #define hex_char(x) ((x) + ((x) < 10 ? '0' : 'A'-10))
      trap_names[i][0] = 't';
      trap_names[i][1] = 'r';
      trap_names[i][2] = 'a';
      trap_names[i][3] = 'p';
      trap_names[i][4] = '_';
      trap_names[i][5] = '0';
      trap_names[i][6] = 'x';
      trap_names[i][7] = hex_char(i>>4);
      trap_names[i][8] = hex_char(i&0xF);
      trap_names[i][9] = 0;
    }

    #include "trapnames.gh"
  }

  if(trap < 0 || trap >= 256)
    return "unknown trap";

  return trap_names[trap];
}
