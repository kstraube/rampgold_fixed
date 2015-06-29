//------------------------------------------------------------------------------ 
// File:        tm_cpu_dram.sv
// Author:      Andrew Waterman, Zhangxi Tan
// Description: A DRAM timing model
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

module dram_model (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t dram_request,
                   output bit 	stay_stalled_for_dram);
                   
bit[NTHREADIDMSB+1:0] ntokens,nthreads;
bit mem_req_fifo_empty,mem_wb_fifo_empty;
bit[NTHREADIDMSB:0] mem_req_fifo_head,mem_wb_fifo_head;

(* syn_ramstyle = "select_ram" *) bit [log2x(MAX_MISS_PENALTY)-1:0] stall_count [NTHREAD-1:0];
bit [log2x(MAX_MISS_PENALTY)-1:0]   stall_count_din, stall_count_dout;
bit [NTHREADIDMSB:0]                stall_count_addr;
bit									stall_count_we;

(* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0] stay_stalled_for_dram_mem;
bit 							stay_stalled_for_dram_din, stay_stalled_for_dram_dout, stay_stalled_for_dram_we;
bit [NTHREADIDMSB:0]			stay_stalled_for_dram_addr;

bit [log2x(MAX_MISS_PENALTY)-1:0] mem_busy_counter;

assign mem_wb_fifo_deq = (mem_busy_counter == 0) & dram_request.token_valid & ~mem_wb_fifo_empty & (mem_wb_fifo_head == dram_request.tid);
replay_fifo mem_wb_queue (.gclk(gclk),.rst(rst),.enq(dram_request.token_valid & dram_request.writeback_valid),.enq_data(dram_request.tid),.deq(mem_wb_fifo_deq),.head(mem_wb_fifo_head),.empty(mem_wb_fifo_empty),.full());

assign mem_req_fifo_deq = ~mem_wb_fifo_deq & (mem_busy_counter == 0) & dram_request.token_valid & ~mem_req_fifo_empty & (mem_req_fifo_head == dram_request.tid);
replay_fifo mem_req_queue (.gclk(gclk),.rst(rst),.enq(dram_request.token_valid & (stall_count_dout == 2)),.enq_data(dram_request.tid),.deq(mem_req_fifo_deq),.head(mem_req_fifo_head),.empty(mem_req_fifo_empty),.full());

always_comb begin
 //ram signals
 stall_count_we   = rst;
// stall_count_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stall_count_addr = dram_request.tid;
 stall_count_din  = '0; 		 //default value during rst

 stay_stalled_for_dram_din  = '0; //default value during rst
 stay_stalled_for_dram_we   = rst;
// stay_stalled_for_dram_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stay_stalled_for_dram_addr = dram_request.tid;
 
 if(dram_request.token_valid) begin
    if(dram_request.request_valid) begin
      stall_count_din = dram_conf.access_time;
      stall_count_we  = '1;
      
      stay_stalled_for_dram_din = '1;
      stay_stalled_for_dram_we = '1;
    end
    else begin
      if(stall_count_dout != 0) begin
        stall_count_din = stall_count_dout-1;
        stall_count_we  = stall_count_dout == 1 ? mem_req_fifo_deq : '1;
      end
      else 
        stay_stalled_for_dram_we = '1;
    end
  end
end

//rams
assign stall_count_dout = stall_count[stall_count_addr];
assign stay_stalled_for_dram_dout = stay_stalled_for_dram_mem[stay_stalled_for_dram_addr];
assign stay_stalled_for_dram = stay_stalled_for_dram_dout;
always_ff @(posedge gclk.clk) begin
 if (stall_count_we) stall_count[stall_count_addr]	<= stall_count_din;
 if (stay_stalled_for_dram_we) stay_stalled_for_dram_mem[stay_stalled_for_dram_addr] <= stay_stalled_for_dram_din;
end

always_ff @(posedge gclk.clk) begin
  nthreads <= dma2tm.threads_active+1;
  
  if(rst) begin
    ntokens <= 0;
    mem_busy_counter <= 0;
  end
  else if(run_reg && ntokens == nthreads) begin
    ntokens <= 0;
    if(mem_busy_counter != 0)
      mem_busy_counter <= mem_busy_counter-1;
  end
  else if(dram_request.token_valid) begin

    ntokens <= ntokens+1;
    
    if(mem_wb_fifo_deq | mem_req_fifo_deq)
      mem_busy_counter <= dram_conf.cycle_time;
  
    //synthesis translate_off
    if(mem_wb_fifo_deq)
      $display("@%t: %m WB REQUEST FINISHED from thread %d, qdepth %d",$time,dram_request.tid,mem_wb_queue.count);
    else if(mem_req_fifo_deq)
      $display("@%t: %m REQUEST FINISHED from thread %d, qdepth %d",$time,dram_request.tid,mem_req_queue.count);
    else if(dram_request.request_valid)
      $display("@%t: %m REQUEST from thread %d to addr %x",$time,dram_request.tid,dram_request.request_addr);
    //synthesis translate_on
    
    //if(stay_stalled_for_dram_dout)
    //  $display("@%t: stay_stalled_for_dram=%b, stall_count=%d",$time,stay_stalled_for_dram[dram_request.tid],stall_count[dram_request.tid]);
  end
end

endmodule


module dram_model_fast (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t dram_request,
                   output bit 	stay_stalled_for_dram);
                   
bit[NTHREADIDMSB+1:0] ntokens,nthreads;
bit mem_req_fifo_empty, mem_req_fifo_deq;
bit[NTHREADIDMSB+1:0] mem_req_fifo_head;
bit                 mem_req_fifo_state;     //1-write back

typedef struct {
  bit [log2x(MAX_MISS_PENALTY)-1:0] count;
  bit                               start_count;
}stall_state_type;

(* syn_ramstyle = "select_ram" *) stall_state_type stall_state[NTHREAD-1:0];
stall_state_type                  stall_state_din, stall_state_dout;
bit [NTHREADIDMSB:0]                stall_state_addr;
bit									stall_state_we;

(* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0] stay_stalled_for_dram_mem;
bit 							stay_stalled_for_dram_din, stay_stalled_for_dram_dout, stay_stalled_for_dram_we;
bit [NTHREADIDMSB:0]			stay_stalled_for_dram_addr;

bit [log2x(MAX_MISS_PENALTY)-1:0] mem_busy_counter;

bit get_next_req;


always_comb begin
 get_next_req = (mem_busy_counter == 0) & dram_request.token_valid & ~mem_req_fifo_empty & (mem_req_fifo_head[NTHREADIDMSB:0] == dram_request.tid);
 mem_req_fifo_deq = get_next_req & ((mem_req_fifo_head[NTHREADIDMSB+1] & mem_req_fifo_state) | ~mem_req_fifo_head[NTHREADIDMSB+1]);


 //ram signals
 stall_state_addr = dram_request.tid;
 stall_state_dout = stall_state[stall_state_addr];
 
 
 stall_state_we   = rst;
// stall_count_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stall_state_din  = '{default:0}; 		 //default value during rst

 stay_stalled_for_dram_din  = '0; //default value during rst
 stay_stalled_for_dram_we   = rst;
// stay_stalled_for_dram_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stay_stalled_for_dram_addr = dram_request.tid;
 
 if(dram_request.token_valid && !rst) begin
    if(dram_request.request_valid) begin      
      stay_stalled_for_dram_din = '1;      
      stay_stalled_for_dram_we = '1;
    end
    else begin
      if (mem_req_fifo_deq) begin
        stall_state_din.count       = dram_conf.access_time;
        stall_state_din.start_count = '1;
        stall_state_we = '1;
      end        
      else begin 
        if (stall_state_dout.count != 0)  begin
         stall_state_din.count = stall_state_dout.count-1;
         stall_state_din.start_count = '1;
         stall_state_we  = '1;
        end
        else if (stall_state_dout.start_count) begin
          stall_state_we = '1;
          stay_stalled_for_dram_we = '1;
        end
      end
    end
  end
end

replay_fifo #(.WIDTH(NTHREADIDMSB+2)) mem_req_queue (.*,.enq(dram_request.token_valid & dram_request.request_valid),.enq_data({dram_request.writeback_valid, dram_request.tid}),.deq(mem_req_fifo_deq),.head(mem_req_fifo_head),.empty(mem_req_fifo_empty),.full());

//rams
assign stay_stalled_for_dram_dout = stay_stalled_for_dram_mem[stay_stalled_for_dram_addr];
assign stay_stalled_for_dram = stay_stalled_for_dram_dout;
always_ff @(posedge gclk.clk) begin
 if (stall_state_we) stall_state[stall_state_addr]	<= stall_state_din;
 if (stay_stalled_for_dram_we) stay_stalled_for_dram_mem[stay_stalled_for_dram_addr] <= stay_stalled_for_dram_din;
end

always_ff @(posedge gclk.clk) begin
  nthreads <= dma2tm.threads_active+1;
  
  if(rst) begin
    ntokens <= 0;
    mem_busy_counter <= 0;
    mem_req_fifo_state <= '0;
  end
  else if(run_reg && ntokens == nthreads) begin
    ntokens <= 0;
    if(mem_busy_counter != 0)
      mem_busy_counter <= mem_busy_counter-1;
  end
  else if(dram_request.token_valid) begin

    ntokens <= ntokens+1;
    
    if (get_next_req) begin
      mem_busy_counter <= dram_conf.cycle_time;

      if (mem_req_fifo_head[NTHREADIDMSB+1]) mem_req_fifo_state <= ~mem_req_fifo_state;  
    end
  end
end

endmodule

/*
module dram_model_gsf (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t dram_request,
                   output bit 	stay_stalled_for_dram);
                   
bit[NTHREADIDMSB+1:0] ntokens,nthreads;
bit mem_req_fifo_empty, mem_req_fifo_deq, mem_req_fifo_enq;
bit[NTHREADIDMSB+2:0] mem_req_fifo_head;
bit                 mem_req_fifo_state;     //1-write back

typedef struct {
  bit [log2x(MAX_MISS_PENALTY)-1:0] count;
  bit                               start_count;
}stall_state_type;

(* syn_ramstyle = "select_ram" *) stall_state_type stall_state[NTHREAD-1:0];
stall_state_type                  stall_state_din, stall_state_dout;
bit [NTHREADIDMSB:0]                stall_state_addr;
bit									stall_state_we;

(* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0] stay_stalled_for_dram_mem;
bit 							stay_stalled_for_dram_din, stay_stalled_for_dram_dout, stay_stalled_for_dram_we;
bit [NTHREADIDMSB:0]			stay_stalled_for_dram_addr;

bit [log2x(MAX_MISS_PENALTY)-1:0] mem_busy_counter;

bit get_next_req;

//highest two bits in fifo: 00 - read only request, 01 - write only request, 10 - write back followed by read

bit [1:0] enq_state;

always_comb begin
 get_next_req = (mem_busy_counter == 0) & dram_request.token_valid & ~mem_req_fifo_empty & (mem_req_fifo_head[NTHREADIDMSB:0] == dram_request.tid);
 mem_req_fifo_deq = get_next_req & ((mem_req_fifo_head[NTHREADIDMSB+2] & mem_req_fifo_state) | ~mem_req_fifo_head[NTHREADIDMSB+2]);

 enq_state  = {dram_request.request_valid & dram_request.writeback_valid, dram_request.writeback_valid & ~dram_request.request_valid};
 mem_req_fifo_enq = dram_request.token_valid & (dram_request.request_valid | dram_request.writeback_valid);

 //ram signals
 stall_state_dout = stall_state[stall_state_addr];
 
 stall_state_we   = rst;
// stall_count_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stall_state_addr = dram_request.tid;
 stall_state_din  = '{default:0}; 		 //default value during rst

 stay_stalled_for_dram_din  = '0; //default value during rst
 stay_stalled_for_dram_we   = rst;
// stay_stalled_for_dram_addr = (rst) ? tm2cpu.tid : dram_request.tid;
 stay_stalled_for_dram_addr = dram_request.tid;
 
 if(dram_request.token_valid && !rst) begin
    if(dram_request.request_valid) begin      
      stay_stalled_for_dram_din = '1;      
      stay_stalled_for_dram_we = ~(enq_state == 2'b01);
    end
    else begin
      if (mem_req_fifo_deq & ~mem_req_fifo_head[NTHREADIDMSB+1]) begin
        stall_state_din.count       = dram_conf.access_time;
        stall_state_din.start_count = '1;
        stall_state_we = '1;
      end        
      else begin 
        if (stall_state_dout.count != 0)  begin
         stall_state_din.count = stall_state_dout.count-1;
         stall_state_we  = '1;
        end
        else if (stall_state_dout.start_count) begin
          stall_state_we = '1;
          stay_stalled_for_dram_we = '1;
        end
      end
    end
  end
end

replay_fifo #(.WIDTH(NTHREADIDMSB+2)) mem_req_queue (.*,.enq(mem_req_fifo_enq),.enq_data({enq_state, dram_request.tid}),.deq(mem_req_fifo_deq),.head(mem_req_fifo_head),.empty(mem_req_fifo_empty),.full());

//rams
assign stay_stalled_for_dram_dout = stay_stalled_for_dram_mem[stay_stalled_for_dram_addr];
assign stay_stalled_for_dram = stay_stalled_for_dram_dout;
always_ff @(posedge gclk.clk) begin
 if (stall_state_we) stall_state[stall_state_addr]	<= stall_state_din;
 if (stay_stalled_for_dram_we) stay_stalled_for_dram_mem[stay_stalled_for_dram_addr] <= stay_stalled_for_dram_din;
end

always_ff @(posedge gclk.clk) begin
  nthreads <= dma2tm.threads_active+1;
  
  if(rst) begin
    ntokens <= 0;
    mem_busy_counter <= 0;
    mem_req_fifo_state <= '0;
  end
  else if(run_reg && ntokens == nthreads) begin
    ntokens <= 0;
    if(mem_busy_counter != 0)
      mem_busy_counter <= mem_busy_counter-1;
  end
  else if(dram_request.token_valid) begin

    ntokens <= ntokens+1;
    
    if (get_next_req) begin
      mem_busy_counter <= dram_conf.cycle_time;

      if (mem_req_fifo_head[NTHREADIDMSB+2]) mem_req_fifo_state <= ~mem_req_fifo_state;  
    end
  end
end

endmodule
*/  