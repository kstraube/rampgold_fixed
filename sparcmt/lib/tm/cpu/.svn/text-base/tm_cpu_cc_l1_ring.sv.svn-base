//------------------------------------------------------------------------------ 
// File:        tm_cpu_cc_l1_ring.sv
// Author:      A. Waterman, Z. Tan, H. Cook
// Description: L1 timing model with ring based performance counters
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
import libconf::*;
import libiu::*;
import libio::*;
import libstd::*;
import libdebug::*;
import libtm::*;
import libopcodes::*;
import libtm_cache::*;
`else
`include "../../cpu/libiu.sv"
`include "../../io/libio.sv"
`include "../libtm.sv"
`include "libtm_cache.sv"
`endif


module tm_cpu_cc_l1  (input iu_clk_type gclk, input bit rst, input run_reg,
                   input l1d_conf_t l1d_conf,
                   input l1i_conf_t l1i_conf,
                   input l2_conf_t l2_conf,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_cpu_ctrl_token_type cpu2tm,
                   input bit [NPARTITIONIDMSB:0] memreq_partition_id,
                   output bit                  stay_stalled,
                   output bit [NTHREADIDMSB:0] l1_cpu2tm_tid_out,
                   output bit                  l1_cpu2tm_valid_out,
                   output l1_counters_t        l1_ctrs,
                   output l2_counters_t        l2_ctrs);
                   
(* syn_maxfan = 8 *) tm_pipe_reg_t tm_pipe[4]; 
tm_pipe_reg_t     v_tm_pipe[4];
bit stay_stalled_for_mem_system;
tm_mem_request_t mem_system_request;

always_ff @(posedge gclk.clk)
  tm_pipe <= v_tm_pipe;

// zeroth TM cycle, decode insn & L1 cache indices/tags
bit[31-L1I_MIN_OFFSET_BITS:0] l1i_line_addr;
bit[31-L1D_MIN_OFFSET_BITS:0] l1d_line_addr;
always_comb begin
  v_tm_pipe[0].cpu2tm = cpu2tm;
  v_tm_pipe[0].partitionid = memreq_partition_id;

  classify_inst(v_tm_pipe[0].cpu2tm.inst,v_tm_pipe[0].inst_type.ldst,v_tm_pipe[0].inst_type.st,v_tm_pipe[0].inst_type.cti,v_tm_pipe[0].inst_type.flop,v_tm_pipe[0].inst_type.intop,v_tm_pipe[0].inst_type.rw_state);
  
  v_tm_pipe[0].l1i_tag = cpu2tm.npc & l1i_conf.tag_mask;
  v_tm_pipe[0].l1d_tag = cpu2tm.paddr & l1d_conf.tag_mask;
        
  l1i_line_addr = cpu2tm.npc[31:L1I_MIN_OFFSET_BITS] >> l1i_conf.additional_offset;
  l1d_line_addr = cpu2tm.paddr[31:L1D_MIN_OFFSET_BITS] >> l1d_conf.additional_offset;
  
  v_tm_pipe[0].l1i_target_idx = l1i_line_addr[L1I_MAX_IDX_BITS-1:0] & l1i_conf.target_index_mask;
  v_tm_pipe[0].l1i_tag_ram_bank_num = v_tm_pipe[0].l1i_target_idx >> l1i_conf.tag_ram_bank_shift;
  v_tm_pipe[0].l1i_tag_ram_idx = l1i_line_addr[L1I_TAG_RAM_IDX_BITS-1:0] & l1i_conf.tag_ram_index_mask;
  //if(l1i_conf.private)
  for(int i = 0; i < NTHREADIDMSB+1; i++)
    v_tm_pipe[0].l1i_tag_ram_idx[L1I_TAG_RAM_IDX_BITS-1-i] |= cpu2tm.tid[i];
  
  v_tm_pipe[0].l1d_target_idx = l1d_line_addr[L1D_MAX_IDX_BITS-1:0] & l1d_conf.target_index_mask;
  v_tm_pipe[0].l1d_tag_ram_bank_num = v_tm_pipe[0].l1d_target_idx >> l1d_conf.tag_ram_bank_shift;
  v_tm_pipe[0].l1d_tag_ram_idx = l1d_line_addr[L1D_TAG_RAM_IDX_BITS-1:0] & l1d_conf.tag_ram_index_mask;
  //if(l1d_conf.private)
  for(int i = 0; i < NTHREADIDMSB+1; i++)
    v_tm_pipe[0].l1d_tag_ram_idx[L1D_TAG_RAM_IDX_BITS-1-i] |= cpu2tm.tid[i];
end

// first TM cycle, tag ram lookup
always_comb
  v_tm_pipe[1] = tm_pipe[0];

bit[31:0] l1d_tag_out[L1D_MAX_ASSOC-1:0], l1d_write_data[L1D_MAX_ASSOC-1:0];
bit[31:0] l1i_tag_out[L1I_MAX_ASSOC-1:0], l1i_write_data[L1I_MAX_ASSOC-1:0];
bit l1d_write_en[L1D_MAX_ASSOC-1:0];
bit l1i_write_en[L1I_MAX_ASSOC-1:0];
generate
  genvar i;
  
  for(i = 0; i < L1D_MAX_ASSOC; i++) begin
    tag_ram #(.DEPTH(L1D_MAX_TAGS/L1D_MAX_ASSOC)) l1d_tag_ram (.gclk(gclk),.rst(rst),.read_addr(v_tm_pipe[0].l1d_tag_ram_idx),.read_data(l1d_tag_out[i]),.write_addr(tm_pipe[2].l1d_tag_ram_idx),.write_data(l1d_write_data[i]),.write_en(l1d_write_en[i]));
  end
  for(i = 0; i < L1I_MAX_ASSOC; i++) begin
    tag_ram #(.DEPTH(L1I_MAX_TAGS/L1I_MAX_ASSOC)) l1i_tag_ram (.gclk(gclk),.rst(rst),.read_addr(v_tm_pipe[0].l1i_tag_ram_idx),.read_data(l1i_tag_out[i]),.write_addr(tm_pipe[2].l1i_tag_ram_idx),.write_data(l1i_write_data[i]),.write_en(l1i_write_en[i]));
  end
endgenerate

// second TM cycle, compare tags & check valid bit
always_comb begin
  v_tm_pipe[2] = tm_pipe[1];
  v_tm_pipe[2].l1d_tag_out = l1d_tag_out;
  v_tm_pipe[2].l1i_tag_out = l1i_tag_out;
  
  for(int i = 0; i < L1I_MAX_ASSOC; i++)
    v_tm_pipe[2].l1i_tag_match[i] = ((l1i_tag_out[i] & l1i_conf.tag_mask) == tm_pipe[1].l1i_tag) & l1i_tag_out[i][0];
  for(int i = 0; i < L1D_MAX_ASSOC; i++)
    v_tm_pipe[2].l1d_tag_match[i] = ((l1d_tag_out[i] & l1d_conf.tag_mask) == tm_pipe[1].l1d_tag) & l1d_tag_out[i][0];
end

// L1I replacement policy
bit[15:0] lfsr;
always_ff @(posedge gclk.clk) begin
  if(rst)
    lfsr <= 1;
  else if(v_tm_pipe[3].l1d_miss | v_tm_pipe[3].l1i_miss)
    lfsr <= {lfsr[0]^lfsr[2]^lfsr[3]^lfsr[5],lfsr[15:1]};
end

bit[L1I_MAX_ASSOC_BITS-1:0] l1i_repl_way;
assign l1i_repl_way = lfsr[L1I_MAX_ASSOC_BITS-1:0];
// end L1I replacement policy

// L1D replacement policy
bit[L1D_MAX_ASSOC_BITS-1:0] l1d_repl_way;
assign l1d_repl_way = lfsr[L1D_MAX_ASSOC_BITS-1:0];
// end L1D replacement policy

// third TM cycle, update tags
always_comb begin
  v_tm_pipe[3] = tm_pipe[2];

  v_tm_pipe[3].l1i_miss = tm_pipe[2].cpu2tm.retired & ~(|tm_pipe[2].l1i_tag_match);
  v_tm_pipe[3].l1d_miss = tm_pipe[2].cpu2tm.retired & tm_pipe[2].inst_type.ldst & ~(|tm_pipe[2].l1d_tag_match);
  v_tm_pipe[3].l1i_repl_way_num = (l1i_conf.tag_ram_bank_mux & l1i_repl_way) | (~l1i_conf.tag_ram_bank_mux & tm_pipe[2].l1i_tag_ram_bank_num);
  v_tm_pipe[3].l1d_repl_way_num = (l1d_conf.tag_ram_bank_mux & l1d_repl_way) | (~l1d_conf.tag_ram_bank_mux & tm_pipe[2].l1d_tag_ram_bank_num);
  
  for(int i = 0; i < L1I_MAX_ASSOC; i++) begin
    l1i_write_en[i] = (v_tm_pipe[3].l1i_repl_way_num == i) & v_tm_pipe[3].l1i_miss;
    l1i_write_data[i] = tm_pipe[2].l1i_tag | 1'b1;
  end
  for(int i = 0; i < L1D_MAX_ASSOC; i++) begin
    l1d_write_en[i] = (v_tm_pipe[3].l1d_repl_way_num == i) & v_tm_pipe[3].l1d_miss | tm_pipe[2].l1d_tag_match[i] & tm_pipe[2].inst_type.ldst;
    l1d_write_data[i] = tm_pipe[2].l1d_tag | {tm_pipe[2].inst_type.st,1'b1};
    if(tm_pipe[2].l1d_tag_match[i])
      l1d_write_data[i][1] |= tm_pipe[2].l1d_tag_out[i][1];
  end
end

// third TM cycle, send request to memory system if necessary
// hack for now: assume D$ miss => next cycle I$ hit
always_comb begin
  mem_system_request.token_valid = tm_pipe[3].cpu2tm.valid;
  mem_system_request.tid = tm_pipe[3].cpu2tm.tid;
  mem_system_request.partitionid = tm_pipe[3].partitionid;
  mem_system_request.request_valid = tm_pipe[3].l1d_miss | tm_pipe[3].l1i_miss;
  mem_system_request.request_addr = tm_pipe[3].l1d_miss ? tm_pipe[3].l1d_tag : tm_pipe[3].l1i_tag;
  mem_system_request.writeback_valid = tm_pipe[3].l1d_miss & tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num][1];
  mem_system_request.writeback_addr = tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num];
end

// update performance counters
//always_ff @(posedge gclk.clk) begin
always_comb begin
  l1_ctrs.retired   = tm_pipe[3].cpu2tm.retired;
  l1_ctrs.cti       = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.cti;
  l1_ctrs.flop      = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.flop;
  l1_ctrs.writeback = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & tm_pipe[3].l1d_miss & tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num][1];
  l1_ctrs.readhit   = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & ~tm_pipe[3].inst_type.st & ~tm_pipe[3].l1d_miss;
  l1_ctrs.readmiss  = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & ~tm_pipe[3].inst_type.st &  tm_pipe[3].l1d_miss;
  l1_ctrs.writehit  = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.st   & ~tm_pipe[3].l1d_miss;
  l1_ctrs.writemiss = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.st   &  tm_pipe[3].l1d_miss;
  l1_ctrs.insthit   = tm_pipe[3].cpu2tm.retired & ~tm_pipe[3].l1i_miss;
  l1_ctrs.instmiss  = tm_pipe[3].cpu2tm.retired &  tm_pipe[3].l1i_miss;
end

//outputs to top level
assign stay_stalled = tm_pipe[3].l1d_miss | tm_pipe[3].l1i_miss | stay_stalled_for_mem_system;
assign l1_cpu2tm_tid_out = tm_pipe[3].cpu2tm.tid;
assign l1_cpu2tm_valid_out = tm_pipe[3].cpu2tm.valid;

mem_system my_mem_system(.*,.req(mem_system_request),.stay_stalled(stay_stalled_for_mem_system));

endmodule
