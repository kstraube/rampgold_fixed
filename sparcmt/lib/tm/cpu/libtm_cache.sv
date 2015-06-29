//------------------------------------------------------------------------------ 
// File:        libtm_cache.sv
// Author:      Andrew Waterman
// Description: Data structures for L1 timing models
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
import libiu::*;
import libconf::*;
import libstd::*;
package libtm_cache;
import libiu::*;
import libopcodes::*;
import libtm::*;
import libconf::*;
import libdebug::*;
import libstd::*;
`endif

parameter NPARTITION = 8;
parameter NPARTITIONIDMSB = log2x(NPARTITION)-1;

parameter L1I_MAX_ASSOC = 16;
parameter L1I_MAX_TAGS = 16384;
parameter L1I_MIN_OFFSET_BITS = 4;
parameter L1I_MAX_OFFSET_BITS = 7;

parameter L1D_MAX_ASSOC = 16;
parameter L1D_MAX_TAGS = 16384;
parameter L1D_MIN_OFFSET_BITS = 4;
parameter L1D_MAX_OFFSET_BITS = 7;

parameter L2_MAX_ASSOC = 16;
parameter L2_MAX_TAGS = 65536;
parameter L2_MIN_OFFSET_BITS = 4;
parameter L2_MAX_OFFSET_BITS = 7;
parameter L2_MAX_NUM_BANKS = 4;
parameter L2_NUM_MSHR = 16;
// to utilize the BRAMs efficiently, want max_tags/max_banks/max_assoc >= 1024

parameter MAX_MISS_PENALTY = 512;

parameter L1D_MAX_ASSOC_BITS = log2x(L1D_MAX_ASSOC);
parameter L1D_MAX_IDX_BITS = log2x(L1D_MAX_TAGS);
parameter L1D_TAG_RAM_IDX_BITS = log2x(L1D_MAX_TAGS/L1D_MAX_ASSOC);
parameter L1D_ADDITIONAL_OFFSET_BITS = log2x(L1D_MAX_OFFSET_BITS-L1D_MIN_OFFSET_BITS+1);

parameter L1I_MAX_ASSOC_BITS = log2x(L1I_MAX_ASSOC);
parameter L1I_MAX_IDX_BITS = log2x(L1I_MAX_TAGS);
parameter L1I_TAG_RAM_IDX_BITS = log2x(L1I_MAX_TAGS/L1I_MAX_ASSOC);
parameter L1I_ADDITIONAL_OFFSET_BITS = log2x(L1I_MAX_OFFSET_BITS-L1I_MIN_OFFSET_BITS+1);

parameter L2_MAX_ASSOC_BITS = log2x(L2_MAX_ASSOC);
parameter L2_MAX_IDX_BITS = log2x(L2_MAX_TAGS/L2_MAX_NUM_BANKS);
parameter L2_TAG_RAM_IDX_BITS = log2x(L2_MAX_TAGS/L2_MAX_NUM_BANKS/L2_MAX_ASSOC);
parameter L2_ADDITIONAL_OFFSET_BITS = log2x(L2_MAX_OFFSET_BITS-L2_MIN_OFFSET_BITS+1);

parameter MAX_MEMCONTROLLER = 4;
parameter MEMCONTROLLERLSB = L2_ADDITIONAL_OFFSET_BITS;

typedef struct {
  bit ldst;
  bit st;
  bit cti;
  bit flop;
  bit intop;
  bit rw_state;
} inst_type_t;

typedef struct {
  tm_cpu_ctrl_token_type              cpu2tm;
  inst_type_t                         inst_type;
  bit[NPARTITIONIDMSB:0]              partitionid;

  bit[L1I_TAG_RAM_IDX_BITS-1:0]       l1i_tag_ram_idx;
  bit[L1I_MAX_ASSOC-1:0]              l1i_tag_ram_bank_num;
  bit[L1I_MAX_IDX_BITS-1:0]           l1i_target_idx;
  bit[31:0]                           l1i_tag;
  bit[31:0]                           l1i_tag_out[L1I_MAX_ASSOC-1:0];
  bit[L1I_MAX_ASSOC-1:0]              l1i_tag_match;
  bit                                 l1i_miss;
  bit[L1I_MAX_ASSOC_BITS-1:0]         l1i_repl_way_num;
  
  bit[L1D_TAG_RAM_IDX_BITS-1:0]       l1d_tag_ram_idx;
  bit[L1D_MAX_ASSOC-1:0]              l1d_tag_ram_bank_num;
  bit[L1D_MAX_IDX_BITS-1:0]           l1d_target_idx;
  bit[31:0]                           l1d_tag;
  bit[31:0]                           l1d_tag_out[L1D_MAX_ASSOC-1:0];
  bit[L1D_MAX_ASSOC-1:0]              l1d_tag_match;
  bit                                 l1d_miss;
  bit[L1D_MAX_ASSOC_BITS-1:0]         l1d_repl_way_num;

} tm_pipe_reg_t;

typedef struct packed {
  bit                                valid;
  bit[NTHREADIDMSB:0]                tid;
} tm_mshr_t;

typedef struct {
  bit[NPARTITIONIDMSB:0]              partitionid;
  bit                                 token_valid;
  bit                                 request_valid;
  bit[NTHREADIDMSB:0]                 tid;
  bit                                 stay_stalled;

  bit                                 writeback;  
  bit[L2_TAG_RAM_IDX_BITS-1:0]        tag_ram_idx;
  bit[L2_MAX_ASSOC-1:0]               tag_ram_bank_num;
  bit[L2_MAX_IDX_BITS-1:0]            target_idx;
  bit[31:0]                           addr;
  bit[31:0]                           request_addr;
  bit[31:0]                           tag;
  bit[31:0]                           tag_out[L2_MAX_ASSOC-1:0];
  bit[L2_MAX_ASSOC-1:0]               tag_match;
  bit                                 miss;
  bit                                 hit;
  bit[L2_MAX_ASSOC_BITS-1:0]          repl_way_num;

  tm_mshr_t                           mshr;
} l2_pipe_reg_t;

typedef struct {
  bit[L1I_TAG_RAM_IDX_BITS-1:0]       tag_ram_index_mask;
  bit[L1I_MAX_IDX_BITS-1:0]           target_index_mask;
  bit[L1I_ADDITIONAL_OFFSET_BITS-1:0] additional_offset;
  bit[31:0]                           tag_mask;
  bit[L1I_MAX_ASSOC_BITS-1:0]         tag_ram_bank_shift;
  bit[L1I_MAX_ASSOC-1:0]              tag_ram_bank_mux;
} l1i_conf_t;

typedef struct {
  bit[L1D_TAG_RAM_IDX_BITS-1:0]       tag_ram_index_mask;
  bit[L1D_MAX_IDX_BITS-1:0]           target_index_mask;
  bit[L1D_ADDITIONAL_OFFSET_BITS-1:0] additional_offset;
  bit[31:0]                           tag_mask;
  bit[L1D_MAX_ASSOC_BITS-1:0]         tag_ram_bank_shift;
  bit[L1D_MAX_ASSOC-1:0]              tag_ram_bank_mux;  
} l1d_conf_t;

typedef struct {
  bit[L2_TAG_RAM_IDX_BITS-1:0]        tag_ram_index_mask;
  bit[L2_MAX_IDX_BITS-1:0]            target_index_mask;
  bit[L2_ADDITIONAL_OFFSET_BITS-1:0]  additional_offset;
  bit[31:0]                           tag_mask;
  bit[L2_MAX_ASSOC_BITS-1:0]          tag_ram_bank_shift;
  bit[L2_MAX_ASSOC-1:0]               tag_ram_bank_mux;  
  bit[log2x(MAX_MISS_PENALTY)-1:0]    access_time;
  bit[log2x(log2x(L2_MAX_NUM_BANKS)+1)-1:0] log2_num_banks;
  bit[NPARTITIONIDMSB:0]                way_to_partition_map [L2_MAX_ASSOC-1:0];
} l2_conf_t;

typedef struct {
  bit[log2x(MAX_MISS_PENALTY)-1:0]    access_time;
  bit[log2x(MAX_MISS_PENALTY)-1:0]    cycle_time;
  bit[log2x(MAX_MISS_PENALTY)-1:0]    credits [NPARTITION-1:0];
  bit[log2x(MAX_MISS_PENALTY)-1:0]    cycles_per_gsf_frame;
} dram_conf_t;

typedef struct {
  bit                         retired;
  bit                         cti;
  bit                         flop;
  bit                         writeback;
  bit                         readhit;
  bit                         readmiss;
  bit                         writehit;
  bit                         writemiss;
  bit                         insthit;
  bit                         instmiss;
} l1_counters_t;

typedef struct {
  bit                         hit;
  bit                         miss;
  bit                         writeback;
} l2_counters_t;

typedef struct {
  bit                                token_valid;
  bit [NTHREADIDMSB:0]               tid;
  bit [NPARTITIONIDMSB:0]            partitionid;
  bit                                request_valid;
  bit [31:0]                         request_addr;
  bit                                writeback_valid;
  bit [31:0]                         writeback_addr;
}tm_mem_request_t;

// decode an instruction to determine its type
task automatic classify_inst(input bit [31:0] inst, output bit ldst, output bit st, output bit cti, output bit flop, output bit intop, output bit rw_state);

  bit [1:0] op;
  bit [2:0] op2;
  bit [5:0] op3;

  op = inst[31:30];
  op2 = inst[24:22];
  op3 = inst[24:19];

  ldst = '0;
  st = '0;
  cti = '0;
  flop = '0;
  intop = '0;
  rw_state = '0;

  unique case (op)
  CALL:
    cti = '1;
  FMT2: 	unique case (op2)
      SETHI:
        intop = '1;
      BICC, FBFCC, FBFCC:
        cti = '1;
      default:;
    endcase
  FMT3:	unique case (op3)
      IADD, IAND, IOR, IXOR, ISUB, ANDN, ORN, IXNOR, ADDX, UMUL, SMUL, SUBX, UDIV,
      SDIV, ADDCC, ANDCC, ORCC, XORCC, SUBCC, ANDNCC, ORNCC, XNORCC, ADDXCC, UMULCC,
      SMULCC, SUBXCC, UDIVCC, SDIVCC, TADDCC, TSUBCC, TADDCCTV, TSUBCCTV, MULSCC,
      ISLL, ISRL, ISRA:
        intop = '1;
      RDPSR, RDWIM, RDTBR, WRY, WRPSR, WRWIM, WRTBR, SAVE, RESTORE:
        rw_state = '1;
      JMPL, TICC, RETT:
        cti = '1;
      FPOP1, FPOP2:
        flop = '1;
      default:;
    endcase
   LDST:
     begin
       ldst = '1;
       st = op3[2];
     end
  default:;
  endcase
endtask

`ifndef SYNP94
endpackage
`endif
