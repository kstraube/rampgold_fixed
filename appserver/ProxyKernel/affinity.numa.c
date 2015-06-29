#include <numa.h>
#include <stdio.h>
#include <errno.h>

typedef int int32_t;
typedef unsigned int uint32_t;

 int32_t NUMA_Sockets        = -1;
 int32_t NUMA_CoresPerSocket = -1;

void Affinity_Init(){ 
  int i;

  if (numa_available() < 0) {
    fprintf(stderr, "your system does not support NUMA...\n");
  }else{
    printf("implementing NUMA via <numa.h>\n");
    NUMA_Sockets = numa_max_node()+1;

    // x86 specific
    #define BUFSIZE 32
    unsigned char buf[BUFSIZE];
    memset(buf,0,BUFSIZE);
    numa_node_to_cpus(0,(void*)buf,BUFSIZE);

    NUMA_CoresPerSocket = 0;
    for(i = 0; i < BUFSIZE; i++)
    {
      while(buf[i])
      {
        NUMA_CoresPerSocket++;
        buf[i] >>= 1;
      }
    }

    numa_set_strict(1);
    numa_set_bind_policy(1);

    printf("found %d nodes with %d cores each\n", NUMA_Sockets,NUMA_CoresPerSocket);
  }
  return;
}

void Affinity_Bind_Memory(uint32_t thread){
  nodemask_t nodemask;
  nodemask_zero(&nodemask);
  nodemask_set(&nodemask,(thread/NUMA_CoresPerSocket));
  numa_set_membind(&nodemask);
  return;
}

void Affinity_Bind_Thread(uint32_t thread){
  nodemask_t nodemask;
  nodemask_zero(&nodemask);
  nodemask_set(&nodemask,(thread/NUMA_CoresPerSocket));
  numa_run_on_node((thread/NUMA_CoresPerSocket));
  //numa_bind(&nodemask); // binds both memory and execution
  return;
}

void Affinity_unBind(){
  nodemask_t nodemask;
  nodemask_zero(&nodemask);
  nodemask_set(&nodemask,0);
  numa_set_membind(&nodemask);
  numa_run_on_node(0);
  //numa_bind(&nodemask);
  //numa_set_membind(&numa_all_nodes);
  //numa_bind(&numa_all_nodes);
  return;
}
