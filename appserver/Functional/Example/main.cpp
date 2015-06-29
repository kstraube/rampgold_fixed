#include <Functional/sim.h>
#include <Functional/processor.h>
#include <Functional/disassemble.h>
#include <Common/htif.h>

int main()
{
   char buf[32];
   // a trivial program
   uint32_t myprogram[] = {
     0x90102005,		//	 	mov  5, %o0
     0x92102001,		//		mov  1, %o1
     0x90a22001,		//	1:	deccc  %o0
     0x12bfffff,		//		bne  1b
     0x92526003,		//		 umul  %o1, 3, %o1
     0x01000000,		// 		nop 
     0x01000000			//		nop 
  };

  // SPARC V8 is big endian, so reorder bytes in the above program
  for(int i = 0; i < sizeof(myprogram)/sizeof(uint32_t); i++)
    myprogram[i] = htobe32(myprogram[i]);

  sim_t sim;
  sim.set_memsize(0x10000000);
  sim.set_num_cores(1);

  // load in program at address 0
  sim.lmem().write(0,sizeof(myprogram),(const uint8_t*)myprogram);

  processor_t* p0 = &sim.procs[0];

  // run the program
  while(p0->PC < 5)
  {
    sim.tick();
    printf("@PC = %08x, PSR = %08x, %%o0 = %08x, %%o1 = %08x\n",4*p0->PC,
           p0->PSR.get(), p0->reg(8), p0->reg(9));
  }

  return 0;
}
