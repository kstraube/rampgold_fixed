#include <Common/host.h>

void set_up_timer()
{
  store_iobus(1,0,0x10FFFFF);
}
