/* Author: Andrew Waterman
 *     Parallel Computing Laboratory
 *     Electrical Engineering and Computer Sciences
 *     University of California, Berkeley
 *
 * Copyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the University of California, Berkeley nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
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

#include "memif.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <Common/host.h>

memif_t::error
memif_t::read(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi)
{
  memif_t::error res;

  if((addr & 0x3) || ((len+(addr&0x3))&0x3))
  {
    uint32_t offset = addr & 0x3;
    uint32_t new_addr = addr-offset;
    uint32_t new_len = len+offset;
    if(new_len & 0x3)
    new_len += 4 - (new_len & 0x3);
    uint8_t* new_bytes = (uint8_t*)malloc(new_len);

    res = read(new_addr,new_len,new_bytes,asi);
    memcpy(bytes,new_bytes+offset,len);
    free(new_bytes);
    return res;
  }
  // now we're 4-byte aligned
  
  assert(len % 4 == 0);
  assert(addr % 4 == 0);

  while((addr & (read_chunk_align()-1)) && len > 0 && len < read_chunk_min_size())
  {
    uint32_t word;
    if((res = read_uint32(addr,&word,asi)) != memif_t::OK)
      return res;
    bytes[0] = word >> 24; bytes[1] = word >> 16;
    bytes[2] = word >> 8;  bytes[3] = word;
    addr += 4;
    bytes += 4;
    len -= 4;
  }

  while((addr & (read_chunk_align()-1)) == 0 && len >= read_chunk_min_size() && len > 0)
  {
    uint32_t thissize = read_chunk_max_size();
    if(thissize > len)
      thissize = len;
    thissize = thissize/read_chunk_align()*read_chunk_align();
    if((res = read_chunk(addr,thissize,bytes,asi)) != memif_t::OK)
      return res;
    addr += thissize;
    bytes += thissize;
    len -= thissize;
  }

  while(len > 0)
  {
    uint32_t word;
    if((res = read_uint32(addr,&word,asi)) != memif_t::OK)
      return res;
    bytes[0] = word >> 24; bytes[1] = word >> 16;
    bytes[2] = word >> 8;  bytes[3] = word;
    addr += 4;
    bytes += 4;
    len -= 4;
  }

  return memif_t::OK;
}

memif_t::error
memif_t::write(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi)
{
  memif_t::error res;

  if((addr&0x3) || ((len+(addr&0x3))&0x3))
  {
    uint32_t offset = addr & 0x3;
    uint32_t end_pad = ((len+offset)&0x3) ? 4-((len+offset)&0x3) : 0;
    uint32_t new_addr = addr-offset;
    uint32_t new_len = len + offset + end_pad;
    uint8_t* new_bytes = (uint8_t*)malloc(new_len);

    if(offset)
    {
      uint32_t word;
      if((res = read_uint32(new_addr,&word,asi)) != memif_t::OK)
        return res;
      new_bytes[0] = word >> 24; new_bytes[1] = word >> 16;
      new_bytes[2] = word >> 8;  new_bytes[3] = word;
    }

    if(end_pad)
    {
      uint32_t word;
      if((res = read_uint32(new_addr+new_len-4,&word,asi)) != memif_t::OK)
        return res;
      new_bytes[new_len-4] = word >> 24; new_bytes[new_len-3] = word >> 16;
      new_bytes[new_len-2] = word >> 8;  new_bytes[new_len-1] = word;
    }

    memcpy(new_bytes+offset,bytes,len);

    res = write(new_addr,new_len,new_bytes,asi);
    free(new_bytes);
    return res;
  }
  // now we're 4-byte aligned

  assert(len % 4 == 0);
  assert(addr % 4 == 0);

  while((addr & (write_chunk_align()-1)) && len > 0 && len < write_chunk_min_size())
  {
    uint32_t word = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    if((res = write_uint32(addr,word,asi)) != memif_t::OK)
      return res;
    addr += 4;
    bytes += 4;
    len -= 4;
  }

  while((addr & (write_chunk_align()-1)) == 0 && len >= write_chunk_min_size() && len > 0)
  {
    uint32_t thissize = write_chunk_max_size();
    if(thissize > len)
      thissize = len;
    thissize = thissize/write_chunk_align()*write_chunk_align();
    if((res = write_chunk(addr,thissize,bytes,asi)) != memif_t::OK)
      return res;
    addr += thissize;
    bytes += thissize;
    len -= thissize;
  }

  while(len > 0)
  {
    uint32_t word = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    if((res = write_uint32(addr,word,asi)) != memif_t::OK)
      return res;
    addr += 4;
    bytes += 4;
    len -= 4;
  }

  return memif_t::OK;
}

memif_t::error
memif_t::read_uint8(uint32_t addr, uint8_t* byte, uint8_t asi)
{
  uint32_t offset = addr & 0x3;
  uint32_t word;
  memif_t::error res = read_uint32(addr-offset,&word,asi);
  *byte = (word >> (24-8*offset)) & 0xff;
  return res;
}

memif_t::error
memif_t::write_uint8(uint32_t addr, uint8_t byte, uint8_t asi)
{
  uint32_t offset = addr & 0x3;
  uint32_t word;
  memif_t::error res = read_uint32(addr-offset,&word,asi);
  if(res != memif_t::OK)
    return res;
  word = (word & ~(0xff << (24-8*offset))) | (byte << (24-8*offset));
  return write_uint32(addr-offset,word,asi);
}

memif_t::error
memif_t::read_int8(uint32_t addr, int8_t* word, uint8_t asi)
{
  return read_uint8(addr, (uint8_t*)word, asi);
}

memif_t::error
memif_t::write_int8(uint32_t addr, int8_t word, uint8_t asi)
{
  return write_uint8(addr, (int8_t)word, asi);
}

memif_t::error
memif_t::read_uint16(uint32_t addr, uint16_t* halfword, uint8_t asi)
{
  uint32_t offset = addr & 0x3;
  uint32_t word;
  memif_t::error res = read_uint32(addr-offset,&word,asi);
  *halfword = (word >> (16-8*offset)) & 0xffff;
  return res;
}

memif_t::error
memif_t::write_uint16(uint32_t addr, uint16_t halfword, uint8_t asi)
{
  uint32_t offset = addr & 0x3;
  uint32_t word;
  memif_t::error res = read_uint32(addr-offset,&word,asi);
  if(res != memif_t::OK)
    return res;
  word = (word & ~(0xffff << (16-8*offset))) | (halfword << (16-8*offset));
  return write_uint32(addr-offset,word,asi);
}

memif_t::error
memif_t::read_int16(uint32_t addr, int16_t* word, uint8_t asi)
{
  return read_uint16(addr, (uint16_t*)word, asi);
}

memif_t::error
memif_t::write_int16(uint32_t addr, int16_t word, uint8_t asi)
{
  return write_uint16(addr, (int16_t)word, asi);
}

memif_t::error
memif_t::read_int32(uint32_t addr, int32_t* word, uint8_t asi)
{
  return read_uint32(addr, (uint32_t*)word,asi);
}

memif_t::error
memif_t::write_int32(uint32_t addr, int32_t word, uint8_t asi)
{
  return write_uint32(addr, (int32_t)word,asi);
}

memif_t::error
memif_t::read_uint64(uint32_t addr, uint64_t* word, uint8_t asi)
{
  if(addr & 0x7)
    return memif_t::Misaligned;

  memif_t::error e = read(addr,sizeof(uint64_t),(uint8_t*)word,asi);
  *word = be64toh(*word);
  return e;
}

memif_t::error
memif_t::write_uint64(uint32_t addr, uint64_t word, uint8_t asi)
{
  if(addr & 0x7)
    return memif_t::Misaligned;

  word = htobe64(word);
  return write(addr,sizeof(uint64_t),(const uint8_t*)&word,asi);
}

memif_t::error
memif_t::read_int64(uint32_t addr, int64_t* word, uint8_t asi)
{
  return read_uint64(addr, (uint64_t*)word,asi);
}

memif_t::error
memif_t::write_int64(uint32_t addr, int64_t word, uint8_t asi)
{
  return write_uint64(addr, (int64_t)word,asi);
}
