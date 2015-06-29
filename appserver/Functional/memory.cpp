#include "sim.h"
#include "processor.h"
#include "memory.h"
#include "iobus.h"
#include "cache.h"
#include "config.h"
#include <cstring>
#include <cstdlib>

#define debug_printf

#if PDC_SIZE & (PDC_SIZE-1) != 1
  #error mmu_t::PDC_SIZE must be a power of 2!
#endif

const int mmu_t::offset_mask[4] = {0xFFFFFFFF,0x00FFFFFF,0x0003FFFF,0x00000FFF};

mmu_t::mmu_t(sim_t* _sim, processor_t* _proc, uint8_t* _mem, uint64_t _memsize)
{
  sim = _sim;
  proc = _proc;
  mem = _mem;
  memsize = _memsize;

  control_reg = 0x01000000;
  set_control_register(0);

  context_table_ptr = 0;
  context_reg = 0;
  fault_status_reg = 0;
  fault_address_reg = 0;
  pdc_lfsr = 1;
  flush_pdc();
}

void mmu_t::set_control_register(uint32_t val)
{
  uint32_t mask = CR_E | CR_NF;
  control_reg = (control_reg & ~mask) | (val & mask);
}

void mmu_t::flush_pdc()
{
  proc->flush_icache();
  for(int i = 0; i < PDC_SIZE; i++)
    pdc[i].vpn = -1;
}

void mmu_t::set_fault_address_reg(uint32_t addr)
{
  fault_status_reg |= FSR_FAV;
  fault_address_reg = addr;
}

void mmu_t::set_fault_status_reg(uint32_t pte, uint8_t level, vaddr addr, uint8_t access_type, bool is_supervisor)
{
  uint32_t fault_type = 0;
  switch(pte & 0x3)
  {
    case 0: fault_type = 1; break;
    case 1: error("set_fault_status_reg called with a PTD!"); break;
    case 2: fault_type = !is_supervisor && PTE_ACC(pte) >= 6 ? 3 : 2; break;
    case 3: fault_type = 4; break;
  }

  fault_status_reg = fault_type << 2;
  fault_status_reg |= access_type << 5;
  fault_status_reg |= level << 8;
}

bool mmu_t::check_privilege(uint32_t pte, bool is_fetch, bool is_write, bool is_supervisor)
{
  switch(PTE_ACC(pte))
  {
    case 0: return !is_fetch && !is_write;
    case 1: return !is_fetch;
    case 2: return !is_write;
    case 3: return true;
    case 4: return is_fetch;
    case 5: return !is_fetch && (!is_write || is_supervisor);
    case 6: return !is_write && is_supervisor;
    case 7: return is_supervisor;
  }
  return false;
}

void mmu_t::probe(vaddr addr, uint32_t& pte, paddr& pte_addr, uint32_t& level)
{
  uint32_t index[4] = {context_reg,(addr>>24),(addr>>18)&0x3F,(addr>>12)&0x3F};
  pte = context_table_ptr;

  for(level = 0; ; level++)
  {
    pte_addr = ((pte & ~0x3)<<4) + 4*index[level];
    #if DEBUG_LEVEL >= 4
      if(!sim->silent)
        debug_notice(4,"vaddr = %x, l%dptd_addr = %llx",addr,level,pte_addr);
    #endif
    if(pte_addr >= memsize || (pte_addr & 0x3))
      error("probe(0x%08x): invalid %s!",addr,pte_addr >= memsize ? "physical address" : "PTE");

    pte = be32toh(*(uint32_t*)(mem+pte_addr));
    #if DEBUG_LEVEL >= 4
      if(!sim->silent)
        debug_notice(4,"vaddr = %x, l%dptd = %x",addr,level,pte);
    #endif
    if((pte & 0x3) != 1 || level == 3)
      return;
  }
}

void mmu_t::update_pdc(vaddr addr, uint32_t pte, uint32_t level)
{
  if(PDC_SIZE == 0)
    return;

  int pos = (addr >> 12) & (PDC_SIZE-1);

  // our PDC only understands 4KB pages, so forge a PPN
  // out of the real PPN and the remainder of the VPN
  pdc[pos].ppn = ((uint64_t(pte) << 4) & ~offset_mask[level]) |
                 (addr & ~0xFFF & offset_mask[level]);

  pdc[pos].access[0x8] = check_privilege(pte,1,0,0);
  pdc[pos].access[0x9] = check_privilege(pte,1,0,1);
  pdc[pos].access[0xA] = check_privilege(pte,0,0,0);
  pdc[pos].access[0xB] = check_privilege(pte,0,0,1);
  pdc[pos].access[0xC] = check_privilege(pte,0,1,0);
  pdc[pos].access[0xD] = check_privilege(pte,0,1,1);

  pdc[pos].ctx = context_reg;
  pdc[pos].vpn = addr >> 12;
}

paddr mmu_t::translate_probe(vaddr addr, uint8_t asi, bool is_fetch, bool is_write, bool is_supervisor)
{
  uint32_t pte, level;
  paddr pte_addr;
  uint8_t access_type = asi&1 | ~asi&2 | is_write<<2;

  if((control_reg & 1) == 0) // mmu disabled? make a fake PTE
  {
    level = 3;
    pte = 0xEE | ((addr & ~0xFFF) >> 4);
  }
  else probe(addr,pte,pte_addr,level);

  paddr pa = ((uint64_t(pte) & ~0xFF) << 4) | addr & offset_mask[level];
  if(pa >= memsize)
    pte = 3;

  if((pte & 0x3) != 2 || !check_privilege(pte,is_fetch,is_write,is_supervisor))
  {
    set_fault_status_reg(pte,level,addr,access_type,is_supervisor);
    if(!is_fetch)
      set_fault_address_reg(addr);

    if((control_reg & CR_NF) && asi != 0x9)
      throw trap_nofault;
    else if(is_fetch)
      throw trap_instruction_access_exception;
    else
      throw trap_data_access_exception;
  }

  update_pdc(addr,pte,level);
  return pa;
}

void mmu_t::store_byte(vaddr addr, uint8_t val, uint8_t asi)
{
  paddr pa;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,true,true);
      *(uint8_t*)(mem+pa) = (val);
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      *(uint8_t*)(mem+addr) = (val);
      break;
    default:
      throw trap_data_access_exception;
  }
}

void mmu_t::store_halfword(vaddr addr, uint16_t val, uint8_t asi)
{
  paddr pa;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,true,true);
      *(uint16_t*)(mem+pa) = htobe16(val);
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      *(uint16_t*)(mem+addr) = htobe16(val);
      break;
    default:
      throw trap_data_access_exception;
  }
}

void mmu_t::store_word(vaddr addr, uint32_t val, uint8_t asi)
{
  paddr pa;
  switch(asi)
  {
    case 0x02: sim->iobus-> store_word(addr,val,proc); break;
    case 0x03: store_asi3(addr,val); break;
    case 0x04: store_asi4(addr,val); break;
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,true,true);
      *(uint32_t*)(mem+pa) = htobe32(val);
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      *(uint32_t*)(mem+addr) = htobe32(val);
      break;
    default:
      throw trap_data_access_exception;
  }
}

void mmu_t::store_dword(vaddr addr, uint64_t val, uint8_t asi)
{
  paddr pa;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,true,true);
      *(uint64_t*)(mem+pa) = htobe64(val);
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      *(uint64_t*)(mem+addr) = htobe64(val);
      break;
    default:
      throw trap_data_access_exception;
  }
}

uint8_t mmu_t::load_byte(vaddr addr, uint8_t asi)
{
  paddr pa;
  uint8_t val = 0;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,false,true);
      val = *(uint8_t*)(mem+pa);
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      val = *(uint8_t*)(mem+addr);
      break;
    default:
      throw trap_data_access_exception;
  }
  return val;
}

uint16_t mmu_t::load_halfword(vaddr addr, uint8_t asi)
{
  paddr pa;
  uint16_t val = 0;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,false,true);
      val = be16toh(*(uint16_t*)(mem+pa));
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      val = be16toh(*(uint16_t*)(mem+addr));
      break;
    default:
      throw trap_data_access_exception;
  }
  return val;
}

uint32_t mmu_t::load_word(vaddr addr, uint8_t asi)
{
  paddr pa;
  uint32_t val = 0;
  switch(asi)
  {
    case 0x02: val = sim->iobus->load_word(addr,proc); break;
    case 0x03: val = load_asi3(addr); break;
    case 0x04: val = load_asi4(addr); break;
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,false,true);
      val = be32toh(*(uint32_t*)(mem+pa));
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      val = be32toh(*(uint32_t*)(mem+addr));
      break;
    default:
      throw trap_data_access_exception;
  }
  return val;
}

uint64_t mmu_t::load_dword(vaddr addr, uint8_t asi)
{
  paddr pa;
  uint64_t val = 0;
  switch(asi)
  {
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
      pa = translate(addr,asi,false,false,true);
      val = be64toh(*(uint64_t*)(mem+pa));
      break;
    case 0x1E:
      if(addr >= memsize)
        throw trap_data_access_exception;
      val = be64toh(*(uint64_t*)(mem+addr));
      break;
    default:
      throw trap_data_access_exception;
  }
  return val;
}

void mmu_t::store_asi4(vaddr addr, uint32_t val)
{
  flush_pdc();
  switch(addr >> 8)
  {
    case 0: set_control_register(val); break;
    case 1: context_table_ptr = val & ~0x3; break;
    case 2: context_reg = val & (NCONTEXTS-1); break;
  }
}

uint32_t mmu_t::load_asi4(vaddr addr)
{
  uint32_t t;
  switch(addr >> 8)
  {
    case 0: return control_reg;
    case 1: return context_table_ptr;
    case 2: return context_reg;
    case 3: t = fault_status_reg; fault_status_reg = 0; return t;
    case 4: return fault_address_reg;
    default: return 0;
  }
}

void mmu_t::store_asi3(uint32_t addr, uint32_t val)
{
  if(((addr >> 8) & 0xF) <= 4)
    flush_pdc();
}

uint32_t mmu_t::load_asi3(uint32_t addr)
{
  uint32_t type = (addr >> 8) & 0xF;
  addr = addr & ~0xFFF;

  uint32_t pte, level;
  paddr pte_addr;
  probe(addr & ~0xFFF,pte,pte_addr,level);

  // technically, the SRMMU updates FSR/FAR if the probe fails.
  // but to help catch subtle OS bugs, we just abort the simulator

  if(type < 4 && type == 3-level || type == 4)
    return pte;
  return 0;
}
