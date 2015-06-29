/* Author: Andrew S. Waterman
 *         Parallel Computing Laboratory
 *         Electrical Engineering and Computer Sciences
 *         University of California, Berkeley
 *
 * Copyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <endian.h>
#include "elf.h"
#include "host.h"
#include <cstring>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <assert.h>
#include "util.h"

memimage_t::memimage_t(uint32_t _offset, uint32_t _pagesize)
{
  offset = _offset;
  pagesize = _pagesize;
}

memimage_t::~memimage_t()
{
  for(std::map<uint32_t,uint8_t*>::iterator i = pages.begin(); i != pages.end(); ++i)
    free(i->second);
}

uint8_t* memimage_t::getpage(uint32_t addr)
{
  uint32_t pageaddr = addr/pagesize*pagesize;
  uint8_t* page = pages[pageaddr];
  if(!page)  
    pages[pageaddr] = page = (uint8_t*)calloc(pagesize,1);
  return page;
}

void memimage_t::write(uint32_t addr, uint32_t size, const uint8_t* bytes)
{
  bool null_bytes = bytes == 0;

  while(size > 0)
  {
    uint8_t* page = getpage(addr);
    uint32_t thissize = std::min(size,pagesize-addr%pagesize);
    if(null_bytes)
      memset(page+addr%pagesize,0,thissize);
    else
      memcpy(page+addr%pagesize,bytes,thissize);
    addr += thissize;
    bytes += thissize;
    size -= thissize;
  }
}

void memimage_t::read(uint32_t addr, uint32_t size, uint8_t* bytes)
{
  while(size > 0)
  {
    uint8_t* page = getpage(addr);
    uint32_t thissize = std::min(size,pagesize-addr%pagesize);
    memcpy(bytes,page+addr%pagesize,thissize);
    addr += thissize;
    bytes += thissize;
    size -= thissize;
  }
}

void memimage_t::copy_to_memif(memif_t& memif)
{
  for(std::map<uint32_t,uint8_t*>::const_iterator i = pages.begin(); i != pages.end(); ++i)
    memif.write(i->first+offset,pagesize,i->second);
}

void memimage_t::check_memif(memif_t& memif)
{
  for(std::map<uint32_t,uint8_t*>::const_iterator i = pages.begin(); i != pages.end(); ++i)
  {
    uint8_t bytes[pagesize];
    memif.read(i->first+offset,pagesize,bytes);
    for(int j = 0; j < pagesize; j++)
      if(bytes[j] != i->second[j])
        fprintf(stderr,"memimage_t::check_memif: image[%x] (%02x) != memif[%x] (%02x)\n",i->first+j,i->second[j],i->first+j,bytes[j]);
  }
}

#define endian16(x) (endian_swap ? __bswap_16(x) : (x))
#define endian32(x) (endian_swap ? __bswap_32(x) : (x))

void load_elf(const uint8_t* elf, uint32_t size, bool big_endian, memimage_t* memimage, bool zero_bss, uint32_t* entryp, std::map<std::string,uint32_t>* symtab)
{
  bool endian_swap = (htobe16(1) != 1) == big_endian;

  int base_addr = 0;
  const char magic[] = {0x7f,'E','L','F'};
  Elf32_Ehdr* header = (Elf32_Ehdr*)elf;

  assert(size >= sizeof(Elf32_Ehdr));
  assert(!strncmp(magic,(char*)header->e_ident,4));

  int phoff = endian32(header->e_phoff);
  int phnum = endian16(header->e_phnum);
  assert(size >= phoff+phnum*sizeof(Elf32_Phdr));
  assert(endian16(header->e_phentsize) == sizeof(Elf32_Phdr));

  Elf32_Phdr* program_headers = (Elf32_Phdr*)(elf+phoff);
  for(int i = 0; i < phnum; i++)
  {
    Elf32_Phdr* ph = program_headers+i;
    if(endian32(ph->p_type) == 1)
    {
      int offset = endian32(ph->p_offset);
      int filesz = endian32(ph->p_filesz);
      int va = endian32(ph->p_vaddr);
      int memsz = endian32(ph->p_memsz);
      assert(offset+filesz <= size);

      memimage->write(va,filesz,elf+offset);
      memimage->write(va+filesz,memsz-filesz,0);
    }
  }

  int shoff = endian32(header->e_shoff);
  int shnum = endian16(header->e_shnum);
  assert(endian16(header->e_shentsize) == sizeof(Elf32_Shdr));
  assert(shoff+sizeof(Elf32_Shdr)*shnum <= size);

  Elf32_Shdr* section_headers = (Elf32_Shdr*)(elf+shoff);
  const uint8_t* strtable = NULL;
  Elf32_Sym* symtable = NULL;
  int strtable_size=0,symtable_size=0;

  // find the symbol table
  for(int i = 0; i < shnum; i++)
  {
    if(symtable == NULL && endian32(section_headers[i].sh_type) == 2)
    {
      symtable = (Elf32_Sym*)(elf+endian32(section_headers[i].sh_offset));
      symtable_size = endian32(section_headers[i].sh_size)/sizeof(Elf32_Sym);
      assert((uint8_t*)(symtable+symtable_size)-elf <= size);

      strtable = elf+endian32(section_headers[endian32(section_headers[i].sh_link)].sh_offset);
      strtable_size = endian32(section_headers[endian32(section_headers[i].sh_link)].sh_size);
      assert(strtable+strtable_size-elf <= size);
    }
  }
  assert(symtable);

  for(int i = 1; i < symtable_size; i++)
  {
    assert(endian32(symtable[i].st_name) < strtable_size);
    const char* name = (const char*)strtable+endian32(symtable[i].st_name);

    uint32_t value = endian32(symtable[i].st_value);
    if(endian16(symtable[i].st_shndx) != 0xfff1)
      value += base_addr;

    if(symtab && endian16(symtable[i].st_shndx) != 0)
        (*symtab)[name] = value;
  }

  if(entryp)
    *entryp = base_addr+endian32(header->e_entry);
}
