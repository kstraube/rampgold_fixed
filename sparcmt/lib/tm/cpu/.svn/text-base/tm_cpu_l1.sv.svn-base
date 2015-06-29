//------------------------------------------------------------------------------ 
// File:        tm_cpu_l1.sv
// Author:      Andrew Waterman
// Description: A simple CPU timing model: CPI=1 except for loads and stores
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
`include "tm_cache.sv"
`endif

module tm_cpu_l1  (input iu_clk_type gclk, input bit rst, 
                   input  tm_cpu_ctrl_token_type cpu2tm,
                   input  dma_tm_ctrl_type       dma2tm,     //start and stop everything right now
                   output tm2cpu_token_type      tm2cpu,
                   input  io_bus_in_type         io_in,
                   output io_bus_out_type        io_out,
                   output bit                    tick,
                   output bit                    running);       //pipeline state
                   
bit                     run_reg, v_run_reg;
tm2cpu_token_type  v_tm2cpu, r_tm2cpu;   //output register
tm_pipe_reg_t tm_pipe[4], v_tm_pipe[4];

bit [NTHREAD-1:0] stall,stay_stalled;
bit [NTHREADIDMSB:0] nthreads_done;
bit round_robin, v_round_robin;

bit [NTHREADIDMSB:0] replay_queue_head, next_thread;
bit replay_queue_empty, replay_queue_deq;

bit [63:0] cycle, hostcycle;

l1d_conf_t l1d_conf;
l1i_conf_t l1i_conf;
l2_conf_t l2_conf;
dram_conf_t dram_conf;
tm_mem_request_t mem_system_request;
l2_counters_t l2_ctrs;

bit tm_finished_one_thread, advance_target_cycle;

always_comb begin  
   
  unique case (dma2tm.tm_dbg_ctrl)
  tm_dbg_start: v_run_reg = '1;
  tm_dbg_stop : v_run_reg = '0;
  default     : v_run_reg = run_reg;    
  endcase
    
  advance_target_cycle = (v_run_reg & ~run_reg) | (tm_finished_one_thread & (nthreads_done == dma2tm.threads_active));
  v_round_robin = 1;
  replay_queue_deq = 0;
  
  v_tm2cpu.running = run_reg;
  
  next_thread = r_tm2cpu.tid+1;
  
  if (rst | ~v_run_reg) begin
    v_tm2cpu.tid = next_thread;
    v_tm2cpu.run = 0;
    v_tm2cpu.valid = 0;
  end
  else begin // run_reg=1
    v_round_robin  = advance_target_cycle | round_robin & (r_tm2cpu.tid != dma2tm.threads_active);
    v_tm2cpu.tid = advance_target_cycle ? 0 : next_thread;
    v_tm2cpu.valid = v_round_robin | ~replay_queue_empty;
    v_tm2cpu.run = (v_round_robin & ~stall[v_tm2cpu.tid]) | (~v_round_robin & ~replay_queue_empty);
    if(~v_round_robin)
      v_tm2cpu.tid = replay_queue_head;
    replay_queue_deq = ~replay_queue_empty & ~v_round_robin;
  end
end

assign tick = advance_target_cycle;

replay_fifo replay_queue (.gclk(gclk),.rst,.enq(run_reg & cpu2tm.replay),.enq_data(cpu2tm.tid),.deq(replay_queue_deq),.head(replay_queue_head),.empty(replay_queue_empty),.full());

always_ff @(posedge gclk.clk) begin
    
  r_tm2cpu <= v_tm2cpu;
  tm2cpu <= r_tm2cpu;
  running <= run_reg;

  run_reg <= rst ? 0 : v_run_reg;
  round_robin <= v_round_robin;
  
  if(rst) begin
    cycle <= 0;
    hostcycle <= 0;
    nthreads_done <= 0;
  end
  else if(run_reg) begin    
    hostcycle <= hostcycle+1;
    
    if(advance_target_cycle) begin // last insn retired for this target cycle
      nthreads_done <= 0;
      cycle <= cycle+1;

      //synthesis translate_off
      //$display("@%t: FINISHED TARGET CYCLE %d ON HOST CYCLE %d",$time,cycle,hostcycle);
      //synthesis translate_on
    end
    else if(tm_finished_one_thread)
      nthreads_done <= nthreads_done+1;
  end
end

// performance counter read mux (pipelined)
io_bus_in_type io_in_del1,io_in_del2,io_in_del3,io_in_del4,io_in_del5;
bit[63:0] counter_outs[15:0];
bit[63:0] counter_outs2[7:0];
bit[63:0] counter_outs3[3:0];
bit[63:0] counter_outs4[1:0];
bit[63:0] counter_result_buf[NTHREAD-1:0];
always_ff @(posedge gclk.clk)
begin
  io_in_del1 <= io_in;
  io_in_del2 <= io_in_del1;
  io_in_del3 <= io_in_del2;
  io_in_del4 <= io_in_del3;
  io_in_del5 <= io_in_del4;
  
  for(int i = 0; i < 8; i++)
    counter_outs2[i] <= io_in_del2.addr[3] ? counter_outs[2*i+1] : counter_outs[2*i];

  for(int i = 0; i < 4; i++)
    counter_outs3[i] <= io_in_del3.addr[4] ? counter_outs2[2*i+1] : counter_outs2[2*i];
    
  for(int i = 0; i < 2; i++)
    counter_outs4[i] <= io_in_del4.addr[5] ? counter_outs3[2*i+1] : counter_outs3[2*i];
    
  if(io_in_del4.en && io_in_del5.addr[2] == 0 && ~io_in_del4.replay && ~io_in_del4.rw)
    counter_result_buf[io_in_del5.tid] <= io_in_del5.addr[6] ? counter_outs4[1] : counter_outs4[0];
end

// performance counters
bit[NTHREADIDMSB:0] counter_increment_tid;
bit[15:0] counter_increment_en;
assign counter_outs[0] = cycle;
assign counter_outs[1] = hostcycle;
assign counter_outs[2] = l2_ctrs.hit;
assign counter_outs[3] = l2_ctrs.miss;
assign counter_outs[4] = l2_ctrs.writeback;
assign counter_outs[15] = 0;
generate
  genvar i;
  for(i = 5; i <= 14; i++)
  begin
    perfctr my_perfctr(.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[i]),.increment_addr(counter_increment_tid),.increment_en(counter_increment_en[i]));
  end
endgenerate

// io bus interface for reading performance counters
always_ff @(posedge gclk.clk)
begin
  io_out.rdata <= io_in.addr[2] ? counter_result_buf[io_in.tid][31:0] : counter_result_buf[io_in.tid][63:32];
  
  if(io_in.en && io_in.rw && io_in_del1.addr[IO_AWIDTH-1:IO_AWIDTH-4] == 0) begin
    unique case (io_in_del1.addr[6:2])
    0: ;
    1: l1d_conf.additional_offset  <= io_in.wdata[L1D_ADDITIONAL_OFFSET_BITS-1:0];
    2: l1d_conf.tag_mask           <= io_in.wdata[31:0];
    3: l1d_conf.target_index_mask  <= io_in.wdata[L1D_MAX_IDX_BITS-1:0];
    4: l1d_conf.tag_ram_index_mask <= io_in.wdata[L1D_TAG_RAM_IDX_BITS-1:0];
    5: l1d_conf.bank_mux           <= io_in.wdata[L1D_MAX_ASSOC-1:0];
    6: l1d_conf.bank_shift         <= io_in.wdata[L1D_MAX_ASSOC_BITS-1:0];
    7: ;
    8: ;
    9: l1i_conf.additional_offset  <= io_in.wdata[L1I_ADDITIONAL_OFFSET_BITS-1:0];
    10:l1i_conf.tag_mask           <= io_in.wdata[31:0];
    11:l1i_conf.target_index_mask  <= io_in.wdata[L1I_MAX_IDX_BITS-1:0];
    12:l1i_conf.tag_ram_index_mask <= io_in.wdata[L1I_TAG_RAM_IDX_BITS-1:0];
    13:l1i_conf.bank_mux           <= io_in.wdata[L1I_MAX_ASSOC-1:0];
    14:l1i_conf.bank_shift         <= io_in.wdata[L1I_MAX_ASSOC_BITS-1:0];
    15:;
    16:;
    17: l2_conf.additional_offset  <= io_in.wdata[L2_ADDITIONAL_OFFSET_BITS-1:0];
    18: l2_conf.tag_mask           <= io_in.wdata[31:0];
    19: l2_conf.target_index_mask  <= io_in.wdata[L2_MAX_IDX_BITS-1:0];
    20: l2_conf.tag_ram_index_mask <= io_in.wdata[L2_TAG_RAM_IDX_BITS-1:0];
    21: l2_conf.bank_mux           <= io_in.wdata[L2_MAX_ASSOC-1:0];
    22: l2_conf.bank_shift         <= io_in.wdata[L2_MAX_ASSOC_BITS-1:0];
    23: l2_conf.access_time        <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    24: dram_conf.access_time      <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    25: dram_conf.cycle_time       <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    26:;
    27:;
    28:;
    29:;
    30:;
    31:;
    endcase
  end
  
  //synthesis translate_off
  if(io_in.en && io_in.rw && io_in_del1.addr[6:2] == 23)
    $display("l1d: %d-byte lines",1<<(l1d_conf.additional_offset+L1D_MIN_OFFSET_BITS));
  if(io_in.en && io_in.rw && io_in_del1.addr[6:2] == 23)
    $display("l1i: %d-byte lines",1<<(l1i_conf.additional_offset+L1I_MIN_OFFSET_BITS));
  if(io_in.en && io_in.rw && io_in_del1.addr[6:2] == 23)
    $display("l1i: %d-byte lines",1<<(l2_conf.additional_offset+L2_MIN_OFFSET_BITS));
  //synthesis translate_on
end

always_comb begin
  io_out.retry = io_in.en && ~io_in_del1.addr[2] && ~io_in.rw && ~io_in.replay;
  io_out.irl = 0;
end

always_ff @(posedge gclk.clk)
  tm_pipe <= v_tm_pipe;

// zeroth TM cycle, decode insn & L1 cache indices/tags
bit[31-L1I_MIN_OFFSET_BITS:0] l1i_line_addr;
bit[31-L1D_MIN_OFFSET_BITS:0] l1d_line_addr;
always_comb begin
  v_tm_pipe[0].cpu2tm = cpu2tm;

  classify_inst(v_tm_pipe[0].cpu2tm.inst,v_tm_pipe[0].inst_type.ldst,v_tm_pipe[0].inst_type.st,v_tm_pipe[0].inst_type.cti,v_tm_pipe[0].inst_type.flop,v_tm_pipe[0].inst_type.intop,v_tm_pipe[0].inst_type.rw_state);
  
  v_tm_pipe[0].l1i_tag = cpu2tm.npc & l1i_conf.tag_mask;
  v_tm_pipe[0].l1d_tag = cpu2tm.paddr & l1d_conf.tag_mask;
        
  l1i_line_addr = cpu2tm.npc[31:L1I_MIN_OFFSET_BITS] >> l1i_conf.additional_offset;
  l1d_line_addr = cpu2tm.paddr[31:L1D_MIN_OFFSET_BITS] >> l1d_conf.additional_offset;
  
  v_tm_pipe[0].l1i_target_idx = l1i_line_addr[L1I_MAX_IDX_BITS-1:0] & l1i_conf.target_index_mask;
  v_tm_pipe[0].l1i_bank_num = v_tm_pipe[0].l1i_target_idx >> l1i_conf.bank_shift;
  v_tm_pipe[0].l1i_tag_ram_idx = l1i_line_addr[L1I_TAG_RAM_IDX_BITS-1:0] & l1i_conf.tag_ram_index_mask;
  //if(l1i_conf.private)
  for(int i = 0; i < NTHREADIDMSB+1; i++)
    v_tm_pipe[0].l1i_tag_ram_idx[L1I_TAG_RAM_IDX_BITS-1-i] |= cpu2tm.tid[i];
  
  v_tm_pipe[0].l1d_target_idx = l1d_line_addr[L1D_MAX_IDX_BITS-1:0] & l1d_conf.target_index_mask;
  v_tm_pipe[0].l1d_bank_num = v_tm_pipe[0].l1d_target_idx >> l1d_conf.bank_shift;
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

// third TM cycle, update tags
bit[15:0] lfsr;
always_comb begin
  v_tm_pipe[3] = tm_pipe[2];

  v_tm_pipe[3].l1i_miss = tm_pipe[2].cpu2tm.retired & ~(|tm_pipe[2].l1i_tag_match);
  v_tm_pipe[3].l1d_miss = tm_pipe[2].cpu2tm.retired & tm_pipe[2].inst_type.ldst & ~(|tm_pipe[2].l1d_tag_match);
  v_tm_pipe[3].l1i_repl_way_num = (l1i_conf.bank_mux & lfsr[L1I_MAX_ASSOC_BITS-1:0]) | (~l1i_conf.bank_mux & tm_pipe[2].l1i_bank_num);
  v_tm_pipe[3].l1d_repl_way_num = (l1d_conf.bank_mux & lfsr[L1D_MAX_ASSOC_BITS-1:0]) | (~l1d_conf.bank_mux & tm_pipe[2].l1d_bank_num);
  
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

always_ff @(posedge gclk.clk) begin
  if(rst)
    lfsr <= 1;
  else if(v_tm_pipe[3].l1d_miss | v_tm_pipe[3].l1i_miss)
    lfsr <= {lfsr[0]^lfsr[2]^lfsr[3]^lfsr[5],lfsr[15:1]};
end

// third TM cycle, send request to memory system if necessary
// hack for now: assume D$ miss => next cycle I$ hit
always_comb begin
  mem_system_request.token_valid = tm_pipe[3].cpu2tm.valid;
  mem_system_request.tid = tm_pipe[3].cpu2tm.tid;
  mem_system_request.request_valid = tm_pipe[3].l1d_miss | tm_pipe[3].l1i_miss;
  mem_system_request.request_addr = tm_pipe[3].l1d_miss ? tm_pipe[3].l1d_tag : tm_pipe[3].l1i_tag;
  mem_system_request.writeback_valid = tm_pipe[3].l1d_miss & tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num][1];
  mem_system_request.writeback_addr = tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num];
end

// update performance counters
always_comb begin
  counter_increment_tid    = tm_pipe[3].cpu2tm.tid;
  counter_increment_en[ 5] = tm_pipe[3].cpu2tm.retired;
  counter_increment_en[ 6] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.cti;
  counter_increment_en[ 7] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.flop;
  counter_increment_en[ 8] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & tm_pipe[3].l1d_miss & tm_pipe[3].l1d_tag_out[tm_pipe[3].l1d_repl_way_num][1];
  counter_increment_en[ 9] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & ~tm_pipe[3].inst_type.st & ~tm_pipe[3].l1d_miss;
  counter_increment_en[10] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.ldst & ~tm_pipe[3].inst_type.st &  tm_pipe[3].l1d_miss;
  counter_increment_en[11] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.st & ~tm_pipe[3].l1d_miss;
  counter_increment_en[12] = tm_pipe[3].cpu2tm.retired & tm_pipe[3].inst_type.st &  tm_pipe[3].l1d_miss;
  counter_increment_en[13] = tm_pipe[3].cpu2tm.retired & ~tm_pipe[3].l1i_miss;
  counter_increment_en[14] = tm_pipe[3].cpu2tm.retired &  tm_pipe[3].l1i_miss;
end

always_ff @(posedge gclk.clk) begin    
  // stall for min. 1 cycle on a cache miss
  // then stay stalled until mem system says otherwise
  if(rst)
    stall <= 0;
  else if(tm_pipe[3].cpu2tm.valid)
    stall[tm_pipe[3].cpu2tm.tid] <= tm_pipe[3].l1d_miss | tm_pipe[3].l1i_miss | stay_stalled[tm_pipe[3].cpu2tm.tid];
  
  tm_finished_one_thread <= tm_pipe[3].cpu2tm.valid;
end

l2_model my_l2(.*);
  
endmodule
