#include <Common/sparcfpu.h>
#include <string.h>
#include "kernel.h"
#include "fpu.h"
#include "syscall.h"

void fp_disabled(trap_state_t* state)
{
#ifndef DISABLE_FPU
  uint32 psr,psr_ef_bit;
  __asm__ __volatile__ ("mov %%psr,%0; set 0x1000,%1; wr %0,%1,%%psr; nop;nop;"
                        "nop; mov %%psr,%0" : "=r"(psr),"=r"(psr_ef_bit));

  if(psr & psr_ef_bit)
  {
    state->psr |= psr_ef_bit;

    // set fsr to 0 by default
    uint32 fsr = 0;
    __asm__ __volatile__ ("ld [%0],%%fsr" : : "r"(&fsr) : "memory");
  }
  else
  {
#endif
      emulate_fpu(state,0);
#ifndef DISABLE_FPU
  }
#endif
}

void fp_exception(trap_state_t* state)
{
  char msg[64];
  uint32 trap = (state->fpu_fsr>>14) & 0x7;
  uint32 ieee = state->fpu_fsr & 0x1F;

  // always re-execute.
  if(1 || trap == fp_trap_unimplemented_FPop)
  {
    emulate_fpu(state,state->fpu_fsr);
    return;
  }

  #ifndef SMALL_MEM
    if(trap == fp_trap_IEEE_754_exception)
      ksprintf(msg,"IEEE 754 floating-point exception: 0x%x",ieee);
    else
      ksprintf(msg,"floating-point exception: 0x%x",trap);

    dump_state(state);
  #else
    strcpy(msg,"floating-point exception: 0x");
    itoa16(trap,msg+strlen(msg));
  #endif

  panic(msg);
}

#ifdef SMALL_MEM

void emulate_fpu(trap_state_t* state, uint32 fsr)
{
  panic("tried to execute an FP instruction with no FPU or emulation!");
}

#else

static inline uint32* effective_address(trap_state_t* state, uint32 insn)
{
  uint32 rs1 = state->gpr[(insn>>14)&0x1F];
  uint32 rs2 = state->gpr[insn&0x1F];
  struct { signed int x:13; } s;
  int32 imm = s.x = insn&0x1FFF;

  return (uint32*)((insn & 0x2000) ? rs1+imm : rs1+rs2);
}

static inline uint32 user_load_word(uint32* addr)
{
  return *addr;
}

static inline uint64 user_load_dword(uint64* addr)
{
  return *addr;
}

static inline void user_store_word(uint32* addr, uint32 word)
{
  *addr = word;
}

static inline void user_store_dword(uint64* addr, uint64 dword)
{
  *addr = dword;
}

#define FPU_ASSERT_ALIGN(ptr,align) do { if((uint32)(ptr) & ((align)-1)) { char buf[64]; panic(ksprintf(buf,"FPU: 0x%x not %d-aligned; pc=0x%x",ptr,align,state->pc)); } } while(0)

void dump_fp_state(sparcfpu_t* fpu)
{
  int i;
  char msg[1024];
  ksprintf(msg,"fsr:\t0x%08x\n",fpu->FSR);
  for(i = 0; i < 32; i++)
    ksprintf(msg+strlen(msg),"f%d:\t0x%08x\n",i,fpu->freg[i]);
  __write(1,msg,strlen(msg));
}

void emulate_fpu(trap_state_t* state, uint32 fsr)
{
  static sparcfpu_t fpus[MAX_PROCS];
  static int initialized[MAX_PROCS] = {0};

  int cid = core_id();
  sparcfpu_t* fpu = &fpus[cid];
  if(!initialized[cid])
  {
    sparcfpu_init(fpu);
    initialized[cid] = 1;
  }

  int psr_ef_bit = 0x1000;
  if(state->psr & psr_ef_bit)
  {
    // copy hw fp regs into sw fp regs
    //__asm__ __volatile__ ("st  %%fsr,[%0]"     : : "r"(&fpu->FSR) : "memory");
    __asm__ __volatile__ ("st  %1,[%0]"     : : "r"(&fpu->FSR),"r"(fsr) : "memory");
    __asm__ __volatile__ ("std %%f0, [%0+0]"   : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f2, [%0+8]"   : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f4, [%0+16]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f6, [%0+24]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f8, [%0+32]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f10,[%0+40]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f12,[%0+48]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f14,[%0+56]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f16,[%0+64]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f18,[%0+72]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f20,[%0+80]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f22,[%0+88]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f24,[%0+96]"  : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f26,[%0+104]" : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f28,[%0+112]" : : "r"(fpu->freg) : "memory");
    __asm__ __volatile__ ("std %%f30,[%0+120]" : : "r"(fpu->freg) : "memory");
  }

  int annul = 0;
  uint32* nnpc = state->npc+1;

  uint64 dword;
  uint32 reg,word;
  int32 disp;
  uint32* addr;
  struct { signed int x:22; } disp22;

  uint32 insn = *state->pc;

  //printf("emulating FP instruction %x at pc %x\n",insn,state->pc);

  switch(insn >> 30)
  {
    case 0:
      switch((insn >> 22) & 0x7)
      {
        case 6:
        {
          int cond = (insn>>25)&0xF;
          if(check_fcc[cond][fpu->FSR.fcc])
          {
            if((cond == fccA || cond == fccN) && ((insn>>29)&1))
              annul = 1;
            disp = disp22.x = insn & 0x3FFFFF;
            nnpc = state->pc + disp;
          }
          else if((insn>>29)&1)
            annul = 1;
          break;
        }
        default:
          panic("bad fp op=0");
          break;
      }
      break;
    case 1:
      panic("bad fp op=1");
      break;
    case 2:
      switch((insn >> 19) & 0x3F)
      {
        case 0x34:
          sparcfpu_fpop1(fpu,*(fp_insn_t*)&insn);
          break;
        case 0x35:
          sparcfpu_fpop2(fpu,*(fp_insn_t*)&insn);
          break;
        default:
          panic("bad fp op=2");
          break;
      }
      break;
    case 3:
      switch((insn >> 19) & 0x3F)
      {
        case 0x20:
          sparcfpu_wrregs(fpu,(insn>>25)&0x1F,user_load_word(effective_address(state,insn)));
          break;
        case 0x21: // ldfsr
          addr = effective_address(state,insn);
          FPU_ASSERT_ALIGN(addr,4);
          word = user_load_word(addr);
          sparcfpu_setFSR(fpu,*(fsr_t*)&word);
          break;
        case 0x23:
          addr = effective_address(state,insn);
          reg = (insn>>25)&0x1F;
          FPU_ASSERT_ALIGN(addr,8);
          FPU_ASSERT_ALIGN(reg,2);
          dword = user_load_dword((uint64*)addr);
          sparcfpu_wrregs(fpu,reg,(uint32)(dword>>32));
          sparcfpu_wrregs(fpu,reg+1,(uint32)dword);
          break;
        case 0x24:
          addr = effective_address(state,insn);
          FPU_ASSERT_ALIGN(addr,4);
          user_store_word(addr,sparcfpu_regs(fpu,(insn>>25)&0x1F));
          break;
        case 0x25: // stfsr
          addr = effective_address(state,insn);
          FPU_ASSERT_ALIGN(addr,4);
          user_store_word(addr,*(uint32*)&fpu->FSR);
          fpu->FSR.ftt = 0;
          break;
        case 0x26:
          panic("stdfq");
          break;
        case 0x27:
          addr = effective_address(state,insn);
          reg = (insn>>25)&0x1F;
          FPU_ASSERT_ALIGN(addr,8);
          FPU_ASSERT_ALIGN(reg,2);
          dword = (((uint64)sparcfpu_regs(fpu,reg))<<32)|(uint64)sparcfpu_regs(fpu,reg+1);
          user_store_dword((uint64*)addr,dword);
          break;
        default:
          panic("bad fp op=3");
          break;
      }
      break;
  }

  if(fpu->FSR.ftt)
  {
    fp_exception(state);
  }
  else
  {
    if(!annul)
    {
      state->pc = state->npc;
      state->npc = nnpc;
    }
    else
    {
      state->pc = nnpc;
      state->npc = nnpc+1;
    }
  }

  if(state->psr & psr_ef_bit)
  {
    // copy hw fp regs into sw fp regs
    __asm__ __volatile__ ("ld  [%0],    %%fsr" : : "r"(&fpu->FSR));
    __asm__ __volatile__ ("ldd [%0+0],  %%f0"  : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+8],  %%f2"  : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+16], %%f4"  : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+24], %%f6"  : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+32], %%f8"  : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+40], %%f10" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+48], %%f12" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+56], %%f14" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+64], %%f16" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+72], %%f18" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+80], %%f20" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+88], %%f22" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+96], %%f24" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+104],%%f26" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+112],%%f28" : : "r"(fpu->freg));
    __asm__ __volatile__ ("ldd [%0+120],%%f30" : : "r"(fpu->freg));
  }
}

#endif
