#ifndef _IOBUS_H
#define _IOBUS_H

#include "sim.h"

class iobus_t
{
public:
  iobus_t(sim_t* s) { sim = s; }
  virtual ~iobus_t() {};
  virtual uint32_t load_word(uint32_t addr, processor_t* proc) = 0;
  virtual void store_word(uint32_t addr, uint32_t val, processor_t* proc) = 0;
protected:
  sim_t* sim;
};

class iobus_functional_t : public iobus_t
{
public:
  iobus_functional_t(sim_t* s);
  uint32_t load_word(uint32_t addr, processor_t* proc);
  void store_word(uint32_t addr, uint32_t val, processor_t* proc);
};

#endif
