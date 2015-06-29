//------------------------------------------------------------------------------ 
// File:        tm_cpu_memsystem.sv
// Author:      Andrew Waterman
// Description: A timing model for a manycore memory system
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

module mem_system (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input l2_conf_t l2_conf,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t req,
                   output bit           stay_stalled,
                   output l2_counters_t l2_ctrs);

tm_mem_request_t l2_request[L2_MAX_NUM_BANKS-1:0];

l2_counters_t l2_ctrs_bank[L2_MAX_NUM_BANKS-1:0];
bit[L2_MAX_NUM_BANKS-1:0] stay_stalled_bank;
assign stay_stalled = |stay_stalled_bank;

bit[log2x(L2_MAX_NUM_BANKS)-1:0] l2_bank_mask,v_l2_bank_mask;

always_comb begin
  v_l2_bank_mask = 0;
  v_l2_bank_mask[l2_conf.log2_num_banks] = 1;
  v_l2_bank_mask = v_l2_bank_mask-1;
end
always_ff @(posedge gclk.clk)
  l2_bank_mask <= v_l2_bank_mask;

generate  
  genvar i;
  for(i = 0; i < L2_MAX_NUM_BANKS; i++) begin

    always_comb begin
      l2_request[i].token_valid = req.token_valid;
      l2_request[i].tid = req.tid;
      l2_request[i].partitionid = req.partitionid;
      l2_request[i].request_valid = req.request_valid && i == (l2_bank_mask & req.request_addr[L2_MAX_OFFSET_BITS+log2x(L2_MAX_NUM_BANKS)-1:L2_MAX_OFFSET_BITS]);
      l2_request[i].writeback_valid = req.writeback_valid && i == (l2_bank_mask & req.writeback_addr[L2_MAX_OFFSET_BITS+log2x(L2_MAX_NUM_BANKS)-1:L2_MAX_OFFSET_BITS]);
    
      l2_request[i].request_addr = {req.request_addr[31:L2_MAX_OFFSET_BITS] >> l2_conf.log2_num_banks, req.request_addr[L2_MAX_OFFSET_BITS-1:0]};
      l2_request[i].writeback_addr = {req.writeback_addr[31:L2_MAX_OFFSET_BITS] >> l2_conf.log2_num_banks, req.writeback_addr[L2_MAX_OFFSET_BITS-1:0]};
    end

    l2_model my_l2(.*,.mem_system_request(l2_request[i]),.stay_stalled(stay_stalled_bank[i]),.l2_ctrs(l2_ctrs_bank[i]));
  end
endgenerate

// aggregate the counters from the L2 banks
bit[log2x(L2_MAX_NUM_BANKS)-1:0] hits_this_cycle,v_hits_this_cycle,misses_this_cycle,v_misses_this_cycle,writebacks_this_cycle,v_writebacks_this_cycle;
always_comb begin  
  l2_ctrs.hit = (hits_this_cycle != 0);
  l2_ctrs.miss = (misses_this_cycle != 0);
  l2_ctrs.writeback = (writebacks_this_cycle != 0);

  v_hits_this_cycle = !rst && l2_ctrs.hit ? hits_this_cycle-1 : 0;
  v_misses_this_cycle = !rst && l2_ctrs.miss ? misses_this_cycle-1 : 0;
  v_writebacks_this_cycle = !rst && l2_ctrs.writeback ? writebacks_this_cycle-1 : 0;
  for(int i = 0; i < L2_MAX_NUM_BANKS; i++) begin
    v_hits_this_cycle = v_hits_this_cycle + l2_ctrs_bank[i].hit;
    v_misses_this_cycle = v_misses_this_cycle + l2_ctrs_bank[i].miss;
    v_writebacks_this_cycle = v_writebacks_this_cycle + l2_ctrs_bank[i].writeback;
  end
end

always @(posedge gclk.clk) begin
  hits_this_cycle <= v_hits_this_cycle;
  misses_this_cycle <= v_misses_this_cycle;
  writebacks_this_cycle <= v_writebacks_this_cycle;
end

//synthesis translate_off
always_ff @(posedge gclk.clk) begin
  if(run_reg) begin
    for(int i = 0; i < L2_MAX_NUM_BANKS; i++)
      if(l2_request[i].writeback_valid)
        $display("writeback to bank %x",i);
  end
end
//synthesis translate_on
endmodule