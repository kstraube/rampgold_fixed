#ifdef __cplusplus
#define DPI_LINK_DECL  extern "C" 
#else
#define DPI_LINK_DECL 
#endif

#include "svdpi.h"

typedef struct
{
  int cmd;
  int rw[8];
  int unsigned addr;
  int unsigned data[8];
} request_type;

typedef struct
{
  int unsigned data[8];
} response_type;

DPI_LINK_DECL DPI_DLLESPEC
void
init_driver();

DPI_LINK_DECL DPI_DLLESPEC
void
transfer(const response_type* rep, request_type* req);

DPI_LINK_DECL DPI_DLLESPEC
void
get_request(request_type* req);

DPI_LINK_DECL DPI_DLLESPEC
void
put_response(const response_type* rep);
