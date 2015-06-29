/*
   $Header: /projects/assam/cvsroot/scale/sims/common/MemIF.h,v 1.6 2005/01/19 22:01:54 kbarr Exp $

   Abstract interface to a memory space.

   Copyright (c) 2002 Massachusetts Institute of Technology
   See file COPYING for full licence details.

Contributors:
Krste Asanovic, MIT, krste@cag.lcs.mit.edu
Ronny Krashinsky, MIT, ronny@mit.edu
*/


/*
   Functions return error code if illegal to perform access.

   Endianess is a property of the memory system, and so all host word
   operations handle endianess conversion magically.

   Support for misaligned word accesses depends on memory system.

TODO: Add second set of operations with 64-bit addresses later to
support 64-bit memory spaces.

*/

#ifndef __MEMIF_H
#define __MEMIF_H

#include <stdexcept>
#include <stdint.h>
#include "host.h"

class memif_t
{
public:
    enum error
    {
        OK = 0,
        Protected = 1,
        Misaligned = 2,
        Invalid = 3,
        Internal = 4,
    };

    virtual ~memif_t(){}

    virtual uint32_t read_chunk_align() = 0;
    virtual uint32_t read_chunk_min_size() = 0;
    virtual uint32_t read_chunk_max_size() = 0;
    virtual error read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi = 0x1E) = 0;
    virtual uint32_t write_chunk_align() = 0;
    virtual uint32_t write_chunk_min_size() = 0;
    virtual uint32_t write_chunk_max_size() = 0;
    virtual error write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi = 0x1E) = 0;

    // Read/Write arbitrary byte arrays.
    virtual error read(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi = 0x1E);
    virtual error write(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi = 0x1E);

    // Read/Write 8-bit host word.
    virtual error read_uint8(uint32_t addr, uint8_t* word, uint8_t asi = 0x1E);
    virtual error write_uint8(uint32_t addr, uint8_t word, uint8_t asi = 0x1E);

    virtual error read_int8(uint32_t addr, int8_t* word, uint8_t asi = 0x1E);
    virtual error write_int8(uint32_t addr, int8_t word, uint8_t asi = 0x1E);

    // Read/Write 16-bit host word.
    virtual error read_uint16(uint32_t addr, uint16_t* word, uint8_t asi = 0x1E);
    virtual error write_uint16(uint32_t addr, uint16_t word, uint8_t asi = 0x1E);

    virtual error read_int16(uint32_t addr, int16_t* word, uint8_t asi = 0x1E);
    virtual error write_int16(uint32_t addr, int16_t word, uint8_t asi = 0x1E);

    // Read/Write 32-bit host word.
    virtual error read_uint32(uint32_t addr, uint32_t* word, uint8_t asi = 0x1E) = 0;
    virtual error write_uint32(uint32_t addr, uint32_t word, uint8_t asi = 0x1E) = 0;

    virtual error read_int32(uint32_t addr, int32_t* word, uint8_t asi = 0x1E);
    virtual error write_int32(uint32_t addr, int32_t word, uint8_t asi = 0x1E);

    // Read/Write 64-bit host word.
    virtual error read_uint64(uint32_t addr, uint64_t* word, uint8_t asi = 0x1E);
    virtual error write_uint64(uint32_t addr, uint64_t word, uint8_t asi = 0x1E);

    virtual error read_int64(uint32_t addr, int64_t* word, uint8_t asi = 0x1E);
    virtual error write_int64(uint32_t addr, int64_t word, uint8_t asi = 0x1E);

    // Flush the caches of cores 0 through ncores-1.
    virtual error flush_cache(uint8_t ncores) = 0;
};

class memif_null_t : public memif_t {
public:
    memif_null_t() {};

    virtual uint32_t read_chunk_align() { throw std::logic_error(error_msg); };
    virtual uint32_t read_chunk_min_size() { throw std::logic_error(error_msg); }
    virtual uint32_t read_chunk_max_size() { throw std::logic_error(error_msg); }
    virtual error read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi = 0x1E) { throw std::logic_error(error_msg); }
    virtual uint32_t write_chunk_align() { throw std::logic_error(error_msg); };
    virtual uint32_t write_chunk_min_size() { throw std::logic_error(error_msg); }
    virtual uint32_t write_chunk_max_size() { throw std::logic_error(error_msg); }
    virtual error write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi = 0x1E) { throw std::logic_error(error_msg); }

    error read(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi = 0x1E)	        { throw std::logic_error(error_msg); }
    error write(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi = 0x1E)  { throw std::logic_error(error_msg); }
    error read_uint8(uint32_t addr, uint8_t* word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error write_uint8(uint32_t addr, uint8_t word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error read_int8(uint32_t addr, int8_t* word, uint8_t asi = 0x1E)	 		        { throw std::logic_error(error_msg); }
    error write_int8(uint32_t addr, int8_t word, uint8_t asi = 0x1E)	 		        { throw std::logic_error(error_msg); }
    error read_uint16(uint32_t addr, uint16_t* word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error write_uint16(uint32_t addr, uint16_t word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error read_int16(uint32_t addr, int16_t* word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error write_int16(uint32_t addr, int16_t word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error read_uint32(uint32_t addr, uint32_t* word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error write_uint32(uint32_t addr, uint32_t word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error read_int32(uint32_t addr, int32_t* word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error write_int32(uint32_t addr, int32_t word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error read_uint64(uint32_t addr, uint64_t* word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error write_uint64(uint32_t addr, uint64_t word, uint8_t asi = 0x1E)		        { throw std::logic_error(error_msg); }
    error read_int64(uint32_t addr, int64_t* word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error write_int64(uint32_t addr, int64_t word, uint8_t asi = 0x1E)		            { throw std::logic_error(error_msg); }
    error flush_cache(uint8_t ncores)		                                            { throw std::logic_error(error_msg); }

protected:
    static char* const error_msg;
};

extern memif_null_t null_memif;

#endif // __MEMIF_H
