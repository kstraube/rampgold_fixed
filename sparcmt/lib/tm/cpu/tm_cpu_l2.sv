//------------------------------------------------------------------------------ 
// File:        tm_cpu_l2.sv
// Author:      Andrew Waterman
// Description: An L2 cache timing model
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

(* syn_maxfan=16 *) module l2_model   (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input l2_conf_t l2_conf,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t mem_system_request,
                   output bit           stay_stalled,
                   output l2_counters_t l2_ctrs);

bit stay_stalled_for_dram;
tm_mem_request_t dram_request;
bit[15:0] lfsr;                   
bit[L2_MAX_ASSOC_BITS-1:0] allowed_way;
bit[L2_MAX_ASSOC_BITS-1:0] reverse_allowed_way;
bit[NTHREADIDMSB+1:0] ntokens,nthreads;
bit mem_req_fifo_empty,mem_wb_fifo_empty,mem_busy;
bit[NTHREADIDMSB:0] mem_req_fifo_head,mem_wb_fifo_head;

(* syn_ramstyle = "select_ram" *) bit [log2x(MAX_MISS_PENALTY)-1:0] l2_stall_count [NTHREAD-1:0];
bit [NTHREADIDMSB:0]                l2_stall_count_addr;
bit [log2x(MAX_MISS_PENALTY)-1:0]	l2_stall_count_din, l2_stall_count_dout;
bit									l2_stall_count_we;

(* syn_ramstyle = "select_ram" *) bit[31:0] l2_request_addr[NTHREAD-1:0];
bit [31:0]                        l2_request_addr_dout;
bit                               l2_request_addr_we;

(* syn_ramstyle = "select_ram" *) bit[31:0] l2_writeback_addr[NTHREAD-1:0];
bit [31:0]                        l2_writeback_addr_dout;
bit                               l2_writeback_addr_we;

(* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0] stay_stalled_ram;
bit                               stay_stalled_din, stay_stalled_we;	
bit [NTHREADIDMSB:0]              stay_stalled_waddr;

(* syn_ramstyle = "select_ram" *) tm_mshr_t [L2_NUM_MSHR-1:0] mshr_ram;
tm_mshr_t                         mshr_din, mshr_we, mshr_dout;	
bit [log2x(L2_NUM_MSHR)-1:0]      mshr_waddr;

l2_pipe_reg_t l2_pipe[4], v_l2_pipe[4];

assign mem_wb_fifo_deq_if_mshr_free = ~mem_busy & mem_system_request.token_valid & ~mem_wb_fifo_empty & (mem_wb_fifo_head == mem_system_request.tid);
assign mem_wb_fifo_deq = ~mshr_dout.valid & mem_wb_fifo_deq_if_mshr_free;
replay_fifo mem_wb_queue (.gclk(gclk),.rst(rst),.enq(mem_system_request.token_valid & mem_system_request.writeback_valid),.enq_data(mem_system_request.tid),.deq(mem_wb_fifo_deq),.head(mem_wb_fifo_head),.empty(mem_wb_fifo_empty),.full());

assign mem_req_fifo_deq_if_mshr_free = ~mem_wb_fifo_deq_if_mshr_free & ~mem_busy & mem_system_request.token_valid & ~mem_req_fifo_empty & (mem_req_fifo_head == mem_system_request.tid);
assign mem_req_fifo_deq = ~mshr_dout.valid & mem_req_fifo_deq_if_mshr_free;
replay_fifo mem_req_queue (.gclk(gclk),.rst(rst),.enq(mem_system_request.token_valid & (l2_stall_count_dout == 2)),.enq_data(mem_system_request.tid),.deq(mem_req_fifo_deq),.head(mem_req_fifo_head),.empty(mem_req_fifo_empty),.full());

always_comb begin
  //ram input signals
//  l2_stall_count_addr = (rst) ? tm2cpu.tid : mem_system_request.tid;
  l2_stall_count_addr = mem_system_request.tid;
  l2_stall_count_we  = rst;
  l2_stall_count_din = '0;		//default value for reset
  
  l2_request_addr_we   = '0;
  l2_writeback_addr_we = '0;

  if(mem_system_request.token_valid) begin
    if(mem_system_request.writeback_valid)
      l2_writeback_addr_we = '1;

    if(mem_system_request.request_valid) begin
      l2_stall_count_din = l2_conf.access_time;
      l2_stall_count_we  = '1;
      
      l2_request_addr_we  = '1;
    end
    else begin
      if(l2_stall_count_dout != 0 && (l2_stall_count_dout != 1 || mem_req_fifo_deq)) begin
        l2_stall_count_din = l2_stall_count_dout - 1;
        l2_stall_count_we  = '1;
      end
    end
  end
end

//rams
assign l2_writeback_addr_dout = l2_writeback_addr[mem_system_request.tid];
assign l2_request_addr_dout   = l2_request_addr[mem_system_request.tid];
assign l2_stall_count_dout    = l2_stall_count[l2_stall_count_addr];
always_ff @(posedge gclk.clk) begin
	if (l2_writeback_addr_we)
		l2_writeback_addr[mem_system_request.tid] <= mem_system_request.writeback_addr;
	
	if (l2_request_addr_we)	
		l2_request_addr[mem_system_request.tid] <= mem_system_request.request_addr;

	if (l2_stall_count_we)
		l2_stall_count[l2_stall_count_addr] <= l2_stall_count_din;
end

always_ff @(posedge gclk.clk) begin
  nthreads <= dma2tm.threads_active+1;
  
  if(rst) begin
    ntokens <= 0;
    mem_busy <= 0;
  end
  else if(run_reg && ntokens == nthreads) begin
    ntokens <= 0;
    mem_busy <= 0;
  end
  else if(mem_system_request.token_valid) begin

    ntokens <= ntokens+1;
            
    if(mem_wb_fifo_deq | mem_req_fifo_deq)
      mem_busy <= 1;
  
    //synthesis translate_off
    if(mem_wb_fifo_deq)
      $display("@%t: %m WB REQUEST FINISHED from thread %d, qdepth %d",$time,mem_system_request.tid,mem_wb_queue.count);
    else if(mem_req_fifo_deq)
      $display("@%t: %m REQUEST FINISHED from thread %d, qdepth %d",$time,mem_system_request.tid,mem_req_queue.count);
    else if(mem_system_request.request_valid)
      $display("@%t: %m REQUEST from thread %d to addr %x",$time,mem_system_request.tid,mem_system_request.request_addr);
    //synthesis translate_on
  end
end

bit[31:0] l2_tag_out[L2_MAX_ASSOC-1:0], l2_write_data[L2_MAX_ASSOC-1:0];
bit l2_write_en[L2_MAX_ASSOC-1:0];
generate
  genvar i;
  for(i = 0; i < L2_MAX_ASSOC; i++) begin
    tag_ram #(.DEPTH(1<<L2_TAG_RAM_IDX_BITS)) l2_tag_ram (.gclk(gclk),.rst(rst),.read_addr(v_l2_pipe[0].tag_ram_idx),.read_data(l2_tag_out[i]),.write_addr(l2_pipe[2].tag_ram_idx),.write_data(l2_write_data[i]),.write_en(l2_write_en[i]));
  end
endgenerate

always_ff @(posedge gclk.clk)
  l2_pipe <= v_l2_pipe;

// zeroth L2 cycle; compute index/tag
bit[31-L2_MIN_OFFSET_BITS:0] l2_line_addr;
always_comb begin
  v_l2_pipe[0].partitionid = mem_system_request.partitionid;
  v_l2_pipe[0].token_valid = mem_system_request.token_valid;
  v_l2_pipe[0].request_valid = mem_req_fifo_deq | mem_wb_fifo_deq;
  v_l2_pipe[0].stay_stalled = mem_system_request.request_valid | (l2_stall_count_dout != 0);
  v_l2_pipe[0].mshr = mshr_dout;
  v_l2_pipe[0].tid = mem_system_request.tid;
  
  v_l2_pipe[0].writeback = mem_wb_fifo_deq;
  v_l2_pipe[0].addr = mem_wb_fifo_deq_if_mshr_free ? l2_writeback_addr_dout : l2_request_addr_dout;
  v_l2_pipe[0].request_addr = l2_request_addr_dout;
  
  v_l2_pipe[0].tag = v_l2_pipe[0].addr & l2_conf.tag_mask;
  l2_line_addr = v_l2_pipe[0].addr[31:L2_MIN_OFFSET_BITS] >> l2_conf.additional_offset;

  v_l2_pipe[0].target_idx = l2_line_addr[L2_MAX_IDX_BITS-1:0] & l2_conf.target_index_mask;
  v_l2_pipe[0].tag_ram_bank_num = v_l2_pipe[0].target_idx >> l2_conf.tag_ram_bank_shift;
  v_l2_pipe[0].tag_ram_idx = l2_line_addr[L2_TAG_RAM_IDX_BITS-1:0] & l2_conf.tag_ram_index_mask;
end

// first L2 cycle; tag ram lookup
always_comb
  v_l2_pipe[1] = l2_pipe[0];

// second L2 cycle, compare tags & check valid bit
always_comb begin
  v_l2_pipe[2] = l2_pipe[1];
  v_l2_pipe[2].tag_out = l2_tag_out;
  
  for(int i = 0; i < L2_MAX_ASSOC; i++)
    v_l2_pipe[2].tag_match[i] = ((l2_tag_out[i] & l2_conf.tag_mask) == l2_pipe[1].tag) & l2_tag_out[i][0];
end

// third L2 cycle, update tags
always_comb begin
  v_l2_pipe[3] = l2_pipe[2];

  //calculate whether the randomly selected way is in the right partition 
  //if it is not, pick the next closest one that is
  for(int i = 0; i < L2_MAX_ASSOC; i++) begin
    allowed_way = (lfsr[L2_MAX_ASSOC_BITS-1:0]+i) % L2_MAX_ASSOC;
    if(v_l2_pipe[3].partitionid == l2_conf.way_to_partition_map[allowed_way]) break;
  end

  //due to the use of l2_conf.tag_ram_bank_mux in calculating
  //repl_way_num and the order in which it allows ways to be used,
  //you have to reverse the bit order of the way_num chosen
  //if you want the behavior to be sensible when l2_conf.assoc < L2_MAX_ASSOC
  for(int i = 0; i < L2_MAX_ASSOC_BITS; i++) begin
    reverse_allowed_way[i] = allowed_way[(L2_MAX_ASSOC_BITS-1)-i];
  end 

  // ignore L1 ->L2 writebacks in hit/miss calculation (inclusive L2)
  v_l2_pipe[3].miss = l2_pipe[2].request_valid & ~(|l2_pipe[2].tag_match) & ~l2_pipe[2].writeback;
  v_l2_pipe[3].hit  = l2_pipe[2].request_valid &  (|l2_pipe[2].tag_match) & ~l2_pipe[2].writeback;
  v_l2_pipe[3].repl_way_num = (l2_conf.tag_ram_bank_mux & reverse_allowed_way) | (~l2_conf.tag_ram_bank_mux & l2_pipe[2].tag_ram_bank_num);
  
  for(int i = 0; i < L2_MAX_ASSOC; i++) begin
    l2_write_en[i] = (v_l2_pipe[3].repl_way_num == i) & v_l2_pipe[3].miss | (l2_pipe[2].tag_match[i] & l2_pipe[2].request_valid);
    l2_write_data[i] = l2_pipe[2].tag | {l2_pipe[2].writeback,1'b1};
    if(l2_pipe[2].tag_match[i])
      l2_write_data[i][1] |= l2_pipe[2].tag_out[i][1];
  end
end

always_ff @(posedge gclk.clk) begin
  if(rst)
    lfsr <= 1;
  else if(v_l2_pipe[3].miss)
    lfsr <= {lfsr[0]^lfsr[2]^lfsr[3]^lfsr[5],lfsr[15:1]};
end

always_ff @(posedge gclk.clk) begin
  l2_ctrs.hit       <= ~rst & l2_pipe[3].hit;
  l2_ctrs.miss      <= ~rst & l2_pipe[3].miss;
  l2_ctrs.writeback <= ~rst & l2_pipe[3].miss & l2_pipe[3].tag_out[l2_pipe[3].repl_way_num][1];
end

always_comb begin
// stay_stalled_waddr = (rst) ? tm2cpu.tid : l2_pipe[3].tid;
  stay_stalled_waddr = l2_pipe[3].tid;
  stay_stalled_din   = (rst) ? '0 : ((l2_pipe[3].stay_stalled | stay_stalled_for_dram | l2_pipe[3].miss) & ~l2_pipe[3].hit);
  stay_stalled_we    = rst | l2_pipe[3].token_valid;
 
  // we only reserve/free MSHRs on L2 requests, not writebacks,
  // because writebacks should hit in the inclusive L2
  mshr_we = rst | l2_pipe[3].miss | (l2_pipe[3].token_valid & l2_pipe[3].mshr.valid & (l2_pipe[3].mshr.tid == l2_pipe[3].tid) & ~stay_stalled_din);
  mshr_din.valid = rst ? 0 : l2_pipe[3].miss;
  mshr_din.tid = l2_pipe[3].tid;
  mshr_waddr = l2_pipe[3].request_addr[L2_MAX_OFFSET_BITS+log2x(L2_NUM_MSHR)-1:L2_MAX_OFFSET_BITS];
  if(rst)
    mshr_waddr = tm2cpu.tid[log2x(L2_NUM_MSHR)-1:0];
end

assign mshr_dout = mshr_ram[v_l2_pipe[0].addr[L2_MAX_OFFSET_BITS+log2x(L2_NUM_MSHR)-1:L2_MAX_OFFSET_BITS]];
always_ff @(posedge gclk.clk) if(mshr_we) mshr_ram[mshr_waddr] <= mshr_din;

//always_ff @(posedge gclk.clk) if(mshr_we) $display("%m: mshr[%d].valid <= %d",mshr_waddr,mshr_din.valid);
//always_ff @(posedge gclk.clk) if(l2_pipe[3].token_valid && l2_pipe[3].tid == 0) $display("%m: mshr_we = %d, mshr_waddr = %d, mshr_din.valid = %d, mshr_raddr = %d, mshr_dout.tid = %d, mshr_dout.valid = %d, stay_stalled_we = %d, stay_stalled_din = %d",mshr_we,mshr_waddr,mshr_din.valid,l2_pipe[3].addr[L2_MAX_OFFSET_BITS+log2x(L2_NUM_MSHR)-1:L2_MAX_OFFSET_BITS],l2_pipe[3].mshr.tid,l2_pipe[3].mshr.valid,stay_stalled_we,stay_stalled_din);
//dual port ram
assign stay_stalled = stay_stalled_ram[mem_system_request.tid];
always_ff @(posedge gclk.clk) if (stay_stalled_we)   stay_stalled_ram[stay_stalled_waddr] <= stay_stalled_din;

// send misses to next level in the hierarchy
always_comb begin
  dram_request.partitionid = l2_pipe[3].partitionid;
  dram_request.token_valid = l2_pipe[3].token_valid;
  dram_request.tid = l2_pipe[3].tid;
  dram_request.request_valid = l2_pipe[3].miss;
  dram_request.request_addr = l2_pipe[3].tag;
  dram_request.writeback_valid = l2_pipe[3].miss & l2_pipe[3].tag_out[l2_pipe[3].repl_way_num][1];
  dram_request.writeback_addr = l2_pipe[3].tag_out[l2_pipe[3].repl_way_num];
end

//dram_model my_dram (.*);
dram_gsf_scheduler my_dram_fast (.*);

endmodule
  
