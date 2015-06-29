//------------------------------------------------------------------------------ 
// File:        tm_cpu_simple.sv
// Author:      Andrew Waterman
// Description: A simple CPU timing model. 
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
import libconf::*;
import libiu::*;
import libdebug::*;
import libtm::*;
import libio::*;
import libopcodes::*;
import libstd::*;
`else
`include "../../cpu/libiu.sv"
//`include "../../cpu/libdebug.sv"
`include "../libtm.sv"
`include "../../io/libio.sv"
//`include "../../cpu/opcodes.sv"
`endif

module tm_cpu_simple(input iu_clk_type gclk, input bit rst, 
                     input  tm_cpu_ctrl_token_type cpu2tm,
                     input  dma_tm_ctrl_type       dma2tm,     //start and stop everything right now
                     output tm2cpu_token_type      tm2cpu,
                     input  io_bus_in_type         io_in,
                     output io_bus_out_type        io_out,
                     output bit					   running);
                   
bit                     run_reg, v_run_reg;
tm2cpu_token_type  v_tm2cpu, r_tm2cpu;   //output register
(* syn_preserve=1 *) io_bus_in_type io_in_del1,io_in_del2,io_in_del3,io_in_del4,io_in_del5;

(* syn_preserve=1 *) tm_cpu_ctrl_token_type cpu2tm_del1,cpu2tm_del2,cpu2tm_del3;

bit[63:0] cycle;
bit[63:0] hostcycle;

bit[63:0] counter_outs[15:0];
bit[63:0] counter_outs2[7:0];
bit[63:0] counter_outs3[3:0];
bit[63:0] counter_outs4[1:0];
bit[63:0] counter_result_buf[NTHREAD-1:0];

(* syn_ramstyle = "select_ram" *) bit[7:0] stall[NTHREAD-1:0];
bit [7:0]  stall_wdata, stall_rdata_0, stall_rdata_1, stall_del[0:2];
bit        stall_we, stall_dec;

bit[NTHREADIDMSB:0] nthreads_done;
bit[NTHREAD-1:0] which_threads_done;
bit[2:0]         which_threads_done_del;

bit is_loadstore,is_load,is_store,is_cti,is_fpop,is_intop,is_rw_state;
bit current_thread_done;
bit advance_target_cycle;

parameter L1_MAX_TAGS = 16384;
parameter L1_MAX_ASSOC = 16;
parameter L1_MIN_OFFSET_BITS = 4;
parameter L1_MAX_OFFSET_BITS = 7;
parameter L1_MAX_MISS_PENALTY = 255;

parameter L1_INDEX_MSB = log2x(L1_MAX_TAGS)-1;
parameter L1_TAG_RAM_INDEX_MSB = log2x(L1_MAX_TAGS/L1_MAX_ASSOC)-1;
parameter L1_ASSOC_MSB = log2x(L1_MAX_ASSOC)-1;
parameter L1_OFFSET_LSB = log2x(L1_MIN_OFFSET_BITS);
parameter L1_OFFSET_BITS_MSB = log2x(1+L1_MAX_OFFSET_BITS-L1_MIN_OFFSET_BITS)-1;
parameter L1_MISS_PENALTY_MSB = log2x(1+L1_MAX_MISS_PENALTY)-1;
parameter L1_BANK_SHIFT_MSB = log2x(L1_INDEX_MSB+1)-1;

reg l1_private;
reg[L1_OFFSET_BITS_MSB:0] l1_offset_bits;
reg[31:0] l1_tag_mask;
reg[L1_INDEX_MSB:0] l1_target_index_mask;
reg[L1_TAG_RAM_INDEX_MSB:0] l1_tag_ram_index_mask;
reg[L1_ASSOC_MSB:0] l1_bank_mux;
reg[L1_BANK_SHIFT_MSB:0] l1_bank_shift;
reg[L1_MISS_PENALTY_MSB:0] l1_miss_penalty;

bit [31:0] paddr_sans_offset;

bit [31:0] l1_tags_write_data;
bit [31:0] l1_tags_read_data_way [L1_MAX_ASSOC-1:0];
bit l1_tags_write_en;
bit l1_tags_write_en_way[L1_MAX_ASSOC-1:0];
bit [L1_INDEX_MSB:0] l1_index,l1_index_del1,l1_index_del2,l1_index_del3;
bit [L1_INDEX_MSB:0] l1_tags_bank_index;
bit [L1_ASSOC_MSB:0] r_l1_tags_bank_index,l1_tags_write_set;
(* syn_preserve=1 *) bit [L1_TAG_RAM_INDEX_MSB:0] l1_tag_ram_index,l1_tag_ram_index_del1,l1_tag_ram_index_del2,l1_tag_ram_index_del3;
bit [L1_MAX_ASSOC-1:0] l1_way_hit, r_l1_way_hit;
bit l1_hit;
bit [15:0] l1_lfsr;

always_comb begin
  
  // start timing model when dma is done
  unique case (dma2tm.tm_dbg_ctrl)
  tm_dbg_start: v_run_reg = '1;
  tm_dbg_stop : v_run_reg = '0;
  default     : v_run_reg = run_reg;    
  endcase
  
  v_tm2cpu.valid = 1;

  // send thread id to functional pipeline ifetch
  if (v_run_reg & ~run_reg) begin
    v_tm2cpu.tid = 0;
    v_tm2cpu.run = '1;
  end
  else begin
    v_tm2cpu.tid   = (r_tm2cpu.tid == dma2tm.threads_total) ? 0 : r_tm2cpu.tid + 1;
//    v_tm2cpu.run = (dma2tm.threads_active >= v_tm2cpu.tid) & run_reg & (stall[v_tm2cpu.tid] == 0) & ~which_threads_done[v_tm2cpu.tid];
    v_tm2cpu.run = (dma2tm.threads_active >= v_tm2cpu.tid) & run_reg & (stall_rdata_1 == 0) & ~which_threads_done[v_tm2cpu.tid];
  end
  
  // timing token to functional pipeline 
  tm2cpu = r_tm2cpu;

  // decode instruction for performance counters  
  classify_inst(cpu2tm_del3.inst,is_loadstore,is_store,is_cti,is_fpop,is_intop,is_rw_state);
  is_load = is_loadstore && ~is_store;
  
  // has the thread that's going through the timing model finished its target cycle?
//  current_thread_done = run_reg & (dma2tm.threads_active >= cpu2tm.tid) & (cpu2tm.valid | (stall[cpu2tm.tid] > 0 && ~which_threads_done[cpu2tm.tid]));
  current_thread_done = run_reg & (dma2tm.threads_active >= cpu2tm.tid) & (cpu2tm.valid | (stall_rdata_0 > 0 && ~which_threads_done[cpu2tm.tid]));
  // should we advance to the next target cycle?
  advance_target_cycle = current_thread_done & (nthreads_done == dma2tm.threads_active);
  
  running = run_reg;
end

always_comb begin
  // determine cache index from address
  l1_tag_ram_index = 0;
  if(l1_private)
    for(int i = 0; i < NTHREADIDMSB+1; i++)
      l1_tag_ram_index[L1_TAG_RAM_INDEX_MSB-i] = cpu2tm.tid[i];
  paddr_sans_offset = cpu2tm.paddr[31:L1_OFFSET_LSB] >> l1_offset_bits;
  l1_tag_ram_index |= paddr_sans_offset[L1_TAG_RAM_INDEX_MSB:0] & l1_tag_ram_index_mask;
  l1_index = paddr_sans_offset[L1_INDEX_MSB:0] & l1_target_index_mask;

  for(int i = 0; i < L1_MAX_ASSOC; i++)
    l1_way_hit[i] = l1_tags_read_data_way[i] == (cpu2tm_del2.paddr & l1_tag_mask);
  l1_hit = |r_l1_way_hit;
  
  l1_tags_bank_index = l1_index_del2 >> l1_bank_shift; // do shift 1 cycle before the following
  l1_tags_write_en = run_reg && (dma2tm.threads_active >= cpu2tm_del3.tid) && cpu2tm_del3.valid && is_loadstore && ~l1_hit;
  l1_tags_write_set = (l1_bank_mux & l1_lfsr[L1_ASSOC_MSB:0]) | (~l1_bank_mux & r_l1_tags_bank_index);
  for(int i = 0; i < L1_MAX_ASSOC; i++)
    l1_tags_write_en_way[i] = l1_tags_write_en && l1_tags_write_set == i;
  l1_tags_write_data = cpu2tm_del3.paddr & l1_tag_mask;
  
end

always_ff @(posedge gclk.clk) begin
  if(rst)
    l1_lfsr <= 1;
  else if(l1_tags_write_en) begin
    l1_lfsr[14:0] <= l1_lfsr[15:1];
    l1_lfsr[15] <= l1_lfsr[0]^l1_lfsr[2]^l1_lfsr[3]^l1_lfsr[5];
  end
end

// performance counter read mux (pipelined)
always_ff @(posedge gclk.clk) begin
  
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

// io bus interface for reading performance counters
always_ff @(posedge gclk.clk) begin
    
  io_out.rdata <= io_in.addr[2] ? counter_result_buf[io_in.tid][31:0] : counter_result_buf[io_in.tid][63:32];

  if(rst) begin
    l1_private <= 0;
    l1_offset_bits <= 0;
    l1_tag_mask <= 0;
    l1_target_index_mask <= 0;
    l1_tag_ram_index_mask <= 0;
    l1_bank_mux <= 0;
    l1_bank_shift <= 0;
    l1_miss_penalty <= 0;
  end
  else if(io_in.en && io_in.rw) begin
    unique case (io_in_del1.addr[4:2])
    0: l1_private            <= io_in.wdata[0];
    1: l1_offset_bits        <= io_in.wdata[L1_OFFSET_BITS_MSB:0];
    2: l1_tag_mask           <= io_in.wdata[31:0];
    3: l1_target_index_mask  <= io_in.wdata[L1_INDEX_MSB:0];
    4: l1_tag_ram_index_mask <= io_in.wdata[L1_TAG_RAM_INDEX_MSB:0];
    5: l1_bank_mux           <= io_in.wdata[L1_ASSOC_MSB:0];
    6: l1_bank_shift         <= io_in.wdata[L1_BANK_SHIFT_MSB:0];
    7: l1_miss_penalty       <= io_in.wdata[L1_MISS_PENALTY_MSB:0];
    endcase
  end
end

always_comb begin
  io_out.retry = io_in.en && ~io_in_del1.addr[2] && ~io_in.rw && ~io_in.replay;
  io_out.irl = 0;
end

// performance counter control logic
bit increment_nretired,increment_ncti,increment_nfpop,increment_nldst,increment_ld_hit,increment_ld_miss,increment_st_hit,increment_st_miss;

always_comb
begin
  increment_nretired = run_reg && (dma2tm.threads_active >= cpu2tm_del3.tid) && cpu2tm_del3.valid;
  increment_ncti     = increment_nretired && is_cti;
  increment_nfpop    = increment_nretired && is_fpop;
  increment_nldst     = increment_nretired && is_loadstore;
  increment_ld_hit   = increment_nretired && is_load  &&  l1_hit;
  increment_ld_miss  = increment_nretired && is_load  && ~l1_hit;
  increment_st_hit   = increment_nretired && is_store &&  l1_hit;
  increment_st_miss  = increment_nretired && is_store && ~l1_hit;
end

// performance counters
assign counter_outs[0] = cycle;
assign counter_outs[1] = hostcycle;
perfctr perfctr_nretired(.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[2]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_nretired));
perfctr perfctr_ncti    (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[3]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_ncti));
perfctr perfctr_nfpop   (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[4]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_nfpop));
perfctr perfctr_nldst   (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[5]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_nldst));
perfctr perfctr_ld_hit  (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[6]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_ld_hit));
perfctr perfctr_ld_miss (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[7]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_ld_miss));
perfctr perfctr_st_hit  (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[8]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_st_hit));
perfctr perfctr_st_miss (.gclk(gclk),.rst(rst),.read_addr(io_in_del1.addr[12:7]),.read_data(counter_outs[9]),.increment_addr(cpu2tm_del3.tid),.increment_en(increment_st_miss));
assign counter_outs[10] = 0;
assign counter_outs[11] = 0;
assign counter_outs[12] = 0;
assign counter_outs[13] = 0;
assign counter_outs[14] = 0;
assign counter_outs[15] = 0;


//tag_ram #(.NUM_TAGS(L1_MAX_TAGS)) l1_tag_ram (.gclk(gclk),.rst(rst),.read_addr(l1_index),.read_data(l1_tags_read_data),.write_addr(l1_index_del2),.write_data(l1_tags_write_data),.write_en(l1_tags_write_en));

generate
  genvar i;
  for(i = 0; i < L1_MAX_ASSOC; i++) begin
    tag_ram #(.NUM_TAGS(L1_MAX_TAGS/L1_MAX_ASSOC)) l1_tag_ram (.gclk(gclk),.rst(rst),.read_addr(l1_tag_ram_index),.read_data(l1_tags_read_data_way[i]),.write_addr(l1_tag_ram_index_del3),.write_data(l1_tags_write_data),.write_en(l1_tags_write_en_way[i]));
  end
endgenerate

always_ff @(posedge gclk.clk) begin
  
  r_tm2cpu <=  v_tm2cpu;
  
  r_l1_way_hit <= l1_way_hit;
  r_l1_tags_bank_index <= l1_tags_bank_index[L1_ASSOC_MSB:0];
  
  l1_tag_ram_index_del1 <= l1_tag_ram_index;
  l1_tag_ram_index_del2 <= l1_tag_ram_index_del1;
  l1_tag_ram_index_del3 <= l1_tag_ram_index_del2;
  l1_index_del1 <= l1_index;
  l1_index_del2 <= l1_index_del1;
  l1_index_del3 <= l1_index_del2;
  cpu2tm_del1 <= cpu2tm;
  cpu2tm_del2 <= cpu2tm_del1;
  cpu2tm_del3 <= cpu2tm_del2;
  
  if (rst) begin
    run_reg <= '0;
    hostcycle <= 0;
    which_threads_done <= 0;
    nthreads_done <= 0;
  end
  else begin
    
    run_reg <= v_run_reg;
    if(run_reg) begin
      hostcycle <= hostcycle+1;
      
      if(advance_target_cycle) begin
        cycle <= cycle+1;
        which_threads_done <= 0;
        nthreads_done <= 0;
        
        //synthesis translate_off
        $display("@%t: advancing to target cycle %d", $time, cycle+1);
        //synthesis translate_on
      end
      else if(current_thread_done) begin
        nthreads_done <= nthreads_done+1;
        which_threads_done[cpu2tm.tid] <= '1;
      end
    end
    
    //synthesis translate_off
    if(increment_nretired && is_loadstore)
      $display("cache access: %s %s addr=%x trueidx=%x tagramidx=%x wanttag=%x gottag=%x,%x,%x,%x",(is_store ? "store" : "load"),(l1_hit ? "hit" : "miss"),cpu2tm_del3.paddr,l1_index_del3,l1_tag_ram_index_del3,cpu2tm_del3.paddr & l1_tag_mask,l1_tags_read_data_way[0],l1_tags_read_data_way[1],l1_tags_read_data_way[2],l1_tags_read_data_way[3]);
    else if(increment_nretired)
      $display("@%t: Thread %d has retired an inst, cycle %d", $time, cpu2tm_del3.tid, cycle);
    //synthesis translate_on
  
  /*  
    if(increment_nretired && is_loadstore && ~l1_hit)
      stall[cpu2tm_del3.tid] <= l1_miss_penalty;
    else if(run_reg && stall[cpu2tm_del3.tid] > 0 && ~which_threads_done[cpu2tm_del3.tid])
      stall[cpu2tm_del3.tid] <= stall[cpu2tm_del3.tid]-1;
*/
  end // ~rst

  which_threads_done_del <= {which_threads_done_del[1:0], which_threads_done[cpu2tm.tid]};
end


//lutram for stall
always_comb begin    
   stall_dec   = run_reg & (stall_del[2] > 0) & ~which_threads_done_del[2];
   stall_wdata =  (stall_dec) ? stall_del[2] -1 : l1_miss_penalty;
   stall_we    =  (increment_nretired & is_loadstore & ~l1_hit) | stall_dec;        
end
  
assign stall_rdata_0 = stall[cpu2tm.tid];
assign stall_rdata_1 = stall[v_tm2cpu.tid];
always_ff @(posedge gclk.clk) begin    
   if (stall_we)
     stall[cpu2tm_del3.tid] <= stall_wdata;
    
   stall_del[0] <= stall_rdata_0;    //cpu2tm_del1
   stall_del[1] <= stall_del[0];     //cpu2tm_del2
   stall_del[2] <= stall_del[1];     //cpu2tm_del3
end
  

endmodule

module perfctr(input iu_clk_type gclk, input bit rst, input bit [NTHREADIDMSB:0] read_addr, output bit [63:0] read_data, input bit [NTHREADIDMSB:0] increment_addr, input bit increment_en);
  
  (* syn_preserve=1 *) bit [NTHREADIDMSB:0]  r_inc_addr;
  (* syn_maxfan=16 *)  bit [NTHREADIDMSB:0]  raddr;
  bit [63:0] inc_read_data,inc_write_data;
  (* syn_preserve=1 *) bit r_inc_en;
  (* syn_srlstyle="registers", syn_preserve=1 *) bit 		 ce1, ce2, ce3, ce4;
  bit [63:0] mem_data;
  
  (* syn_ramstyle = "select_ram" *) reg [63:0] myram[NTHREAD-1:0];
  
  
  always_ff @(posedge gclk.clk)
  begin
    r_inc_addr <= increment_addr;
    r_inc_en <= increment_en;
  end
  
  always_ff @(posedge gclk.clk2x) begin
    ce1 <= gclk.ce;
    ce2 <= ce1;
    ce3 <= ce2;
    ce4 <= ce3;
  end
  
  always_comb
  begin
    inc_write_data = inc_read_data+1;
    raddr = (ce4) ? read_addr : increment_addr;
  end
  
  
  assign  mem_data = myram[raddr];
  always_ff @(posedge gclk.clk)
  	read_data <= mem_data;
  	
  always_ff @(negedge gclk.clk)
  	inc_read_data <= mem_data;
  	
  always_ff @(negedge gclk.clk)  begin
      if(r_inc_en)
        myram[r_inc_addr] <= inc_write_data;
  end

endmodule


//module tag_ram(input iu_clk_type gclk, input bit rst, input bit [31:0] read_addr, output bit[31:0] read_data, input bit [31:0] write_addr, input bit [31:0] write_data, input bit write_en);

module tag_ram #(parameter NUM_TAGS=8) (input iu_clk_type gclk, input bit rst, input bit [log2x(NUM_TAGS)-1:0] read_addr, output bit[31:0] read_data, input bit [log2x(NUM_TAGS)-1:0] write_addr, input bit [31:0] write_data, input bit write_en);
//parameter int NUM_TAGS = 8;
parameter int NUMTAGSMSB = log2x(NUM_TAGS)-1;


(* syn_maxfan=4 *) reg [NUMTAGSMSB:0] r_read_addr;
(* syn_maxfan=4 *) reg [NUMTAGSMSB:0] r_write_addr;
(* syn_maxfan=4 *) reg [31:0] r_write_data;
(* syn_maxfan=4 *) reg r_write_en;

reg [31:0] myram[NUM_TAGS-1:0];

  always_ff @(posedge gclk.clk)
  begin
    r_read_addr <= read_addr[NUMTAGSMSB:0];
    r_write_addr <= write_addr[NUMTAGSMSB:0];
    r_write_data <= write_data;
    r_write_en <= write_en;
  end
  
  always_ff @(posedge gclk.clk)
  begin
    read_data <= myram[r_read_addr];
    
    if(r_write_en)
      myram[r_write_addr] <= r_write_data;
  end
  
endmodule

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
