//------------------------------------------------------------------------------ 
// File:        tm_cpu_none.sv
// Author:      Zhangxi Tan
// Description: A simple CPU "timing" model. 
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
import libconf::*;
import libiu::*;
import libdebug::*;
import libtm::*;
`else
`include "../../cpu/libiu.sv"
//`include "../../cpu/libdebug.sv"
`include "../libtm.sv"
`endif

module tm_cpu_none(input iu_clk_type gclk, input bit rst, 
                   input  tm_cpu_ctrl_token_type cpu2tm,
                   input  dma_tm_ctrl_type       dma2tm,     //start and stop everything right now
                   output tm2cpu_token_type      tm2cpu,
                   output bit                    running);       //pipeline state
                   
bit                     run_reg, v_run_reg;
bit [NTHREADIDMSB:0] thread_count;
tm2cpu_token_type  v_tm2cpu, r_tm2cpu;   //output register


//const bit [NTHREAD-1:0] thread_mask = 1;      //thread mask

always_comb begin  
   
  unique case (dma2tm.tm_dbg_ctrl)
  tm_dbg_start: v_run_reg = '1;
  tm_dbg_stop : v_run_reg = '0;
  default     : v_run_reg = run_reg;    
  endcase  

  v_tm2cpu.tid = r_tm2cpu.tid + 1;
  v_tm2cpu.valid = 1;
  
  if (rst) begin
//    v_tm2cpu.tid = r_tm2cpu.tid + 1;
    v_tm2cpu.run = '0;
  end  
  else if (v_run_reg & ~run_reg) begin
    v_tm2cpu.tid = '0;
    v_tm2cpu.run = '1;
  end
  else begin
//    v_tm2cpu.tid   = (r_tm2cpu.tid == dma2tm.threads_total) ? 0 : r_tm2cpu.tid + 1;
    if (r_tm2cpu.tid == dma2tm.threads_total) v_tm2cpu.tid = '0;
    v_tm2cpu.run = (dma2tm.threads_active >= v_tm2cpu.tid) & run_reg;
  end
  
  //output 
  tm2cpu = r_tm2cpu;
  running = run_reg;
end

always_ff @(posedge gclk.clk) begin
  
  r_tm2cpu <= v_tm2cpu;

  if (rst) 
    run_reg <= 0;
  else
    run_reg <= v_run_reg;
  
end

endmodule              





