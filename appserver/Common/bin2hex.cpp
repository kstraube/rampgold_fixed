#include <Common/elf.h>
#include <Common/util.h>
#include <iostream>
using namespace std;

#define LINE_SIZE 32
class hex_memif_t : public memif_t
{
  uint32_t read_chunk_align() { return LINE_SIZE; }
  uint32_t read_chunk_min_size() { return LINE_SIZE; }
  uint32_t read_chunk_max_size() { return LINE_SIZE; }
  uint32_t write_chunk_align() { return LINE_SIZE; }
  uint32_t write_chunk_min_size() { return LINE_SIZE; }
  uint32_t write_chunk_max_size() { return LINE_SIZE; }
  error flush_cache(uint8_t ncores) { throw std::logic_error(""); }
  error read_uint32(uint32_t addr, uint32_t* word, uint8_t asi) { throw std::logic_error(""); }
  error write_uint32(uint32_t addr, uint32_t word, uint8_t asi) { throw std::logic_error(""); }
  error read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi) { throw std::logic_error(""); }
  error write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi)
  {
    if(asi != 0x1E)
      return OK;
    cout << "@" << hex << addr/LINE_SIZE << endl;
    for(int i = LINE_SIZE-1; i >= 0; i--)
      cout << hex << ((uint32_t)bytes[i]>>4&0xF) << ((uint32_t)bytes[i]&0xF);
    cout << endl;
    return OK;
  }
};

int main()
{
  int size; memimage_t memimage(0,LINE_SIZE); hex_memif_t hex;
  uint8_t* file = (uint8_t*)readfile_posix(0,&size);
  load_elf(file,size,&memimage,0,0);
  memimage.copy_to_memif(hex);
  return 0;
}
