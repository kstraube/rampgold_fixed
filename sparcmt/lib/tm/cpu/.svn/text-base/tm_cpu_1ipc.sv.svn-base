//------------------------------------------------------------------------------ 
// File:        tm_cpu_none.sv
// Author:      Zhangxi Tan
// Description: A simple CPU "timing" model. 
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
import libconf::*;
import libiu::*;
import libio::*;
import libstd::*;
import libdebug::*;
import libtm::*;
`else
`include "../../cpu/libiu.sv"
`include "../../io/libio.sv"
`include "../libtm.sv"
`endif

module tm_cpu_1ipc(input iu_clk_type gclk, input bit rst, 
                   input  tm_cpu_ctrl_token_type cpu2tm,
                   input  dma_tm_ctrl_type       dma2tm,     //start and stop everything right now
                   output tm2cpu_token_type      tm2cpu,
                   output bit                    tick,           // new target cycle
                   output bit                    running);       //pipeline state
                   
bit                     run_reg, v_run_reg;
tm2cpu_token_type  v_tm2cpu, r_tm2cpu;   //output register

bit [NTHREADIDMSB:0] nthreads_done;
bit advance_target_cycle;
bit round_robin, v_round_robin;

bit [NTHREADIDMSB:0] replay_queue_head, next_thread;
bit replay_queue_empty, replay_queue_deq;

bit [63:0] cycle, hostcycle;

always_comb begin  
   
  unique case (dma2tm.tm_dbg_ctrl)
  tm_dbg_start: v_run_reg = '1;
  tm_dbg_stop : v_run_reg = '0;
  default     : v_run_reg = run_reg;    
  endcase
  
  v_round_robin = 1;
  replay_queue_deq = 0;
  
  v_tm2cpu.running = run_reg;
  
  next_thread = r_tm2cpu.tid+1;
  
  if (rst) begin
    v_tm2cpu.tid = next_thread;
    v_tm2cpu.valid = 0;
  end
  else if (~v_run_reg) begin
    v_tm2cpu.tid = r_tm2cpu.tid == dma2tm.threads_total ? 0 : next_thread;
    v_tm2cpu.valid = 0;
  end
  else if (v_run_reg & ~run_reg) begin
    v_tm2cpu.tid = 0;
    v_tm2cpu.valid = 1;
  end
  else begin // run_reg=1
    v_round_robin  = advance_target_cycle | round_robin & (r_tm2cpu.tid != dma2tm.threads_active);
    v_tm2cpu.tid = advance_target_cycle ? 0 : (v_round_robin ? next_thread : replay_queue_head);
    v_tm2cpu.valid = v_round_robin | ~replay_queue_empty;
    replay_queue_deq = ~replay_queue_empty & ~v_round_robin;
  end
  
  v_tm2cpu.run = v_tm2cpu.valid;
  
  //output 
  tm2cpu = r_tm2cpu;
  running = run_reg;
end

assign advance_target_cycle = cpu2tm.valid & (nthreads_done == dma2tm.threads_active);
assign tick = advance_target_cycle;
  
replay_fifo replay_queue (.gclk,.rst,.enq(run_reg & cpu2tm.replay),.enq_data(cpu2tm.tid),.deq(replay_queue_deq),.head(replay_queue_head),.empty(replay_queue_empty),.full());

always_ff @(posedge gclk.clk) begin
  
  r_tm2cpu <= v_tm2cpu;
  run_reg <= rst ? 0 : v_run_reg;
  round_robin <= v_round_robin;
    
  
  if(v_run_reg & ~run_reg) begin
    cycle <= 0;
    hostcycle <= 0;
    
    nthreads_done <= '0;
  end
  else if(run_reg) begin
    
    hostcycle <= hostcycle+1;
    
    if(advance_target_cycle) begin // last insn retired for this target cycle
      nthreads_done <= 0;
      cycle <= cycle+1;
    end
    else if(cpu2tm.valid) begin // current thread retired an insn
      nthreads_done <= nthreads_done+1;
    end
    
    //synthesis translate_off
    if(advance_target_cycle)
      $display("@%t: FINISHED TARGET CYCLE %d ON HOST CYCLE %d",$time,cycle,hostcycle);
    //synthesis translate_on
  end
  
end

endmodule

module replay_fifo #(parameter DEPTH=NTHREAD, parameter WIDTH=NTHREADIDMSB+1)
  (input iu_clk_type gclk, input bit rst, input bit enq,
   input bit[WIDTH-1:0] enq_data, input bit deq,
   output bit[WIDTH-1:0] head, output bit empty, output bit full);
   
   parameter NDEPTHMSB = log2x(DEPTH)-1;
   bit might_be_empty;
   (* syn_maxfan = 16 *) bit[NDEPTHMSB:0] head_ptr, tail_ptr;
   (* syn_ramstyle = "select_ram" *)  bit[WIDTH-1:0] ram[DEPTH-1:0];
   always_comb begin
     empty = (head_ptr == tail_ptr) & might_be_empty;
     full = (head_ptr == tail_ptr) & ~might_be_empty;
     head = ram[head_ptr];
   end

  always_ff @(posedge gclk.clk) begin
  
    if(rst) begin
      head_ptr <= 0;
      tail_ptr <= 0;
      might_be_empty <= 1;
    end
    else begin
    
      if(enq) begin
        ram[tail_ptr] <= enq_data;
      	tail_ptr <= tail_ptr+1;
      end
    
      if(deq)
        head_ptr <= head_ptr+1;
      
      
      might_be_empty <= (deq|enq) ? deq & ~enq : might_be_empty;
   
    end
  
  end

endmodule
