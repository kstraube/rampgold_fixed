//------------------------------------------------------------------------------ 
// File:        tm_cpu_cc_top.sv
// Author:      A. Waterman, Z. Tan, H. Cook
// Description: Top level module for the TM
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


module tm_cpu_cc_top #(parameter NHOSTGLOBALCNT=12) (input iu_clk_type gclk, input bit rst, 
                   input  tm_cpu_ctrl_token_type cpu2tm,
                   input  dma_tm_ctrl_type       dma2tm,     //start and stop everything right now
                   output tm2cpu_token_type      tm2cpu /* synthesis syn_maxfan=16 */,
                   input  io_bus_in_type         io_in,
                   output io_bus_out_type        io_out,
                   input  bit [NHOSTGLOBALCNT-1:0] host_global_perf_counter,
                   output bit                    tick,
                   output bit                    running);       //pipeline state
                   
bit                run_reg, v_run_reg;
tm2cpu_token_type  v_tm2cpu, r_tm2cpu;   //output register

(* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0] stall_ram;
bit                stall_din, stall_we;

bit [NTHREADIDMSB:0] nthreads_done;
bit round_robin, v_round_robin;
bit [NTHREADIDMSB:0] replay_queue_head, next_thread;
bit replay_queue_empty, replay_queue_deq;

bit [63:0] cycle;

//signals to and from l1
l1d_conf_t l1d_conf;
l1i_conf_t l1i_conf;
l2_conf_t l2_conf;
dram_conf_t dram_conf;
bit[NPARTITIONIDMSB:0] memreq_partition_id;
bit	stay_stalled;
bit [NTHREADIDMSB:0] l1_cpu2tm_tid_out;
bit                  l1_cpu2tm_valid_out;
l1_counters_t l1_ctrs;
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
    v_tm2cpu.run = (v_round_robin & ~stall_ram[v_tm2cpu.tid]) | (~v_round_robin & ~replay_queue_empty);  //read port of stall ram
    if(~v_round_robin)
      v_tm2cpu.tid = replay_queue_head;
    replay_queue_deq = ~replay_queue_empty & ~v_round_robin;
  end
end

assign tick = advance_target_cycle;

replay_fifo replay_queue (.gclk(gclk),.rst,.enq(cpu2tm.replay),.enq_data(cpu2tm.tid),.deq(replay_queue_deq),.head(replay_queue_head),.empty(replay_queue_empty),.full());

always_ff @(posedge gclk.clk) begin
    
  r_tm2cpu <= v_tm2cpu;
  tm2cpu <= r_tm2cpu;
  running <= run_reg;

  run_reg <= rst ? 0 : v_run_reg;
  round_robin <= v_round_robin;
  
  if(rst) begin
     //synthesis translate_off
    cycle <= 0;
    //synthesis translate_on
    nthreads_done <= 0;
  end
  else if(run_reg) begin
    
    if(advance_target_cycle) begin // last insn retired for this target cycle
      nthreads_done <= 0;

      //synthesis translate_off
      cycle <= cycle+1;
      $display("@%t: FINISHED TARGET CYCLE %d",$time,cycle);
      //synthesis translate_on
    end
    else if(tm_finished_one_thread)
      nthreads_done <= nthreads_done+1;
  end
end


// performance counters
bit [NTHREADIDMSB:0] local_counter_tid[0:9];
bit [9:0] local_counter_inc;
bit [5+NHOSTGLOBALCNT-1:0] global_counter_inc;

// io bus interface for reading performance counters
perfctr_io #(.NLOCAL(10), .NGLOBAL(5+NHOSTGLOBALCNT)) gen_tm_counter(.gclk, .rst,
                  .bus_out(io_out),
                  .bus_in(io_in),
                  .bus_sel(),
                  //counter signals
                  .global_inc(global_counter_inc),
                  .local_inc(local_counter_inc),
                  .local_tid(local_counter_tid)
                  );

io_bus_in_type io_in_del1;
always_ff @(posedge gclk.clk) begin  
  io_in_del1 <= io_in;

  if(io_in.en && io_in.rw && io_in_del1.addr[IO_AWIDTH-1:IO_AWIDTH-4] == 0 && io_in_del1.addr[IO_AWIDTH-5:NTHREADIDMSB+3] == 0) begin
    unique case (io_in_del1.addr[7:2])
    0: ;
    1: l1d_conf.additional_offset  <= io_in.wdata[L1D_ADDITIONAL_OFFSET_BITS-1:0];
    2: l1d_conf.tag_mask           <= io_in.wdata[31:0];
    3: l1d_conf.target_index_mask  <= io_in.wdata[L1D_MAX_IDX_BITS-1:0];
    4: l1d_conf.tag_ram_index_mask <= io_in.wdata[L1D_TAG_RAM_IDX_BITS-1:0];
    5: l1d_conf.tag_ram_bank_mux   <= io_in.wdata[L1D_MAX_ASSOC-1:0];
    6: l1d_conf.tag_ram_bank_shift <= io_in.wdata[L1D_MAX_ASSOC_BITS-1:0];
    7: ;
    8: ;
    9: l1i_conf.additional_offset  <= io_in.wdata[L1I_ADDITIONAL_OFFSET_BITS-1:0];
    10:l1i_conf.tag_mask           <= io_in.wdata[31:0];
    11:l1i_conf.target_index_mask  <= io_in.wdata[L1I_MAX_IDX_BITS-1:0];
    12:l1i_conf.tag_ram_index_mask <= io_in.wdata[L1I_TAG_RAM_IDX_BITS-1:0];
    13:l1i_conf.tag_ram_bank_mux   <= io_in.wdata[L1I_MAX_ASSOC-1:0];
    14:l1i_conf.tag_ram_bank_shift <= io_in.wdata[L1I_MAX_ASSOC_BITS-1:0];
    15:;
    16: l2_conf.log2_num_banks     <= io_in.wdata[log2x(log2x(L2_MAX_NUM_BANKS)+1)-1:0];
    17: l2_conf.additional_offset  <= io_in.wdata[L2_ADDITIONAL_OFFSET_BITS-1:0];
    18: l2_conf.tag_mask           <= io_in.wdata[31:0];
    19: l2_conf.target_index_mask  <= io_in.wdata[L2_MAX_IDX_BITS-1:0];
    20: l2_conf.tag_ram_index_mask <= io_in.wdata[L2_TAG_RAM_IDX_BITS-1:0];
    21: l2_conf.tag_ram_bank_mux   <= io_in.wdata[L2_MAX_ASSOC-1:0];
    22: l2_conf.tag_ram_bank_shift <= io_in.wdata[L2_MAX_ASSOC_BITS-1:0];
    23: l2_conf.access_time        <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    24: dram_conf.access_time      <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    25: dram_conf.cycle_time       <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    26: dram_conf.cycles_per_gsf_frame <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
    27:;
    28:;
    29:;
    30:;
    31:;
    default:;
    endcase
  end
  
  //synthesis translate_off
  if(io_in.en && io_in.rw && &io_in_del1.addr[7:2]) begin
    $display("l1d:  %d-byte lines",1<<(l1d_conf.additional_offset+L1D_MIN_OFFSET_BITS));
    $display("l1i:  %d-byte lines",1<<(l1i_conf.additional_offset+L1I_MIN_OFFSET_BITS));
    $display("l2:   %d-byte lines, %d banks",1<<(l2_conf.additional_offset+L2_MIN_OFFSET_BITS),1<<l2_conf.log2_num_banks);
    $display("dram: %d-cycle latency, %d-cycle inverse throughput",dram_conf.access_time,dram_conf.cycle_time);
  end
  //synthesis translate_on
end

// partition ID RAM
bit[NPARTITIONIDMSB:0] partition_id_ram[NTHREAD-1:0];
bit partition_id_w_en;
assign partition_id_w_en = io_in.en && io_in.rw && io_in_del1.addr[IO_AWIDTH-1:IO_AWIDTH-4] == 0 && io_in_del1.addr[IO_AWIDTH-5:NTHREADIDMSB+3] == 1;
bit[NTHREADIDMSB:0] partition_id_w_addr, partition_id_r_addr;
assign partition_id_w_addr = io_in_del1.addr[NTHREADIDMSB+2:2];
assign partition_id_r_addr = cpu2tm.tid;
always_ff @(posedge gclk.clk) begin
  if(partition_id_w_en)
    partition_id_ram[partition_id_w_addr] <= io_in.wdata[NPARTITIONIDMSB:0];
  memreq_partition_id <= partition_id_ram[partition_id_r_addr];
end

// partition credits RAM
bit partition_credits_w_en;
assign partition_credits_w_en = io_in.en && io_in.rw && io_in_del1.addr[IO_AWIDTH-1:IO_AWIDTH-4] == 0 && io_in_del1.addr[IO_AWIDTH-5:NTHREADIDMSB+3] == 0 && io_in_del1.addr[7] == 1 && io_in_del1.addr[6:NPARTITIONIDMSB+3] == 0;
bit[NPARTITIONIDMSB:0] partition_credits_w_addr;
assign partition_credits_w_addr = io_in_del1.addr[NPARTITIONIDMSB+2:2];
always_ff @(posedge gclk.clk) begin
  if(partition_credits_w_en)
    dram_conf.credits[partition_credits_w_addr] <= io_in.wdata[log2x(MAX_MISS_PENALTY)-1:0];
end

// l2 way to partition map RAM
bit l2_way_to_partition_map_w_en;
assign l2_way_to_partition_map_w_en = io_in.en && io_in.rw && io_in_del1.addr[IO_AWIDTH-1:IO_AWIDTH-4] == 0 && io_in_del1.addr[IO_AWIDTH-5:NTHREADIDMSB+4] == 1 && io_in_del1.addr[8:L2_MAX_ASSOC_BITS+2] == 0;
bit[L2_MAX_ASSOC_BITS-1:0] l2_way_to_partition_map_w_addr;
assign l2_way_to_partition_map_w_addr = io_in_del1.addr[L2_MAX_ASSOC_BITS-1+2:2];
always_ff @(posedge gclk.clk) begin
  if(l2_way_to_partition_map_w_en)
    l2_conf.way_to_partition_map[l2_way_to_partition_map_w_addr] <= io_in.wdata[NPARTITIONIDMSB:0];
end

// update performance counters
always_ff @(posedge gclk.clk) begin
  for (int i=0; i<10; i++) local_counter_tid[i] <= l1_cpu2tm_tid_out;

  local_counter_inc[0] <= l1_ctrs.retired;
  local_counter_inc[1] <= l1_ctrs.cti;
  local_counter_inc[2] <= l1_ctrs.flop;
  local_counter_inc[3] <= l1_ctrs.writeback;
  local_counter_inc[4] <= l1_ctrs.readhit;
  local_counter_inc[5] <= l1_ctrs.readmiss;
  local_counter_inc[6] <= l1_ctrs.writehit;
  local_counter_inc[7] <= l1_ctrs.writemiss;
  local_counter_inc[8] <= l1_ctrs.insthit;
  local_counter_inc[9] <= l1_ctrs.instmiss;
  
  global_counter_inc[0] <= ~rst & run_reg & advance_target_cycle;
  global_counter_inc[1] <= ~rst & run_reg;
  global_counter_inc[2] <= l2_ctrs.hit;
  global_counter_inc[3] <= l2_ctrs.miss;
  global_counter_inc[4] <= l2_ctrs.writeback;
  
  if (NHOSTGLOBALCNT) begin
   global_counter_inc[5 +: NHOSTGLOBALCNT] <= host_global_perf_counter;
  end
end

always_comb begin
	stall_din = (rst) ? '0 : stay_stalled;
	stall_we  = rst | l1_cpu2tm_valid_out;
end

always_ff @(posedge gclk.clk) begin    
  // stall for min. 1 cycle on a cache miss
  // then stay stalled until mem system says otherwise
  if(stall_we)
    stall_ram[l1_cpu2tm_tid_out] <= stall_din;
  
  tm_finished_one_thread <= l1_cpu2tm_valid_out;
end

tm_cpu_cc_l1 my_l1(.*,.tm2cpu(r_tm2cpu)); //TODO:remove tm2cpu forwarding entirely

//synthesis translate_off
int cycles_stalled[NTHREAD-1:0];
always_ff @(posedge gclk.clk) begin
  if(cpu2tm.valid & ~cpu2tm.retired) begin
    cycles_stalled[cpu2tm.tid] <= cycles_stalled[cpu2tm.tid]+1;
    if(cycles_stalled[cpu2tm.tid] == NTHREAD*2*(dram_conf.cycle_time+l2_conf.access_time+10)) begin
      $display("thread %d stalled too long!",cpu2tm.tid);
      $stop(0);
    end
  end
  else if(cpu2tm.valid) begin
    cycles_stalled[cpu2tm.tid] <= 0;
  end
end
//synthesis translate_on
  
endmodule
