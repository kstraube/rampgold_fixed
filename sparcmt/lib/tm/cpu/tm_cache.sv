//------------------------------------------------------------------------------ 
// File:        tm_cache.sv
// Author:      Andrew Waterman
// Description: Data structures for cache timing models
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

// a RAM with one read port and one write port
module tag_ram #(parameter DEPTH=8, parameter WIDTH=32) (input iu_clk_type gclk, input bit rst, input bit [log2x(DEPTH)-1:0] read_addr, output bit[WIDTH-1:0] read_data, input bit [log2x(DEPTH)-1:0] write_addr, input bit [WIDTH-1:0] write_data, input bit write_en);

//  (* syn_maxfan=4 *) reg [log2x(DEPTH)-1:0] r_read_addr;
  (* syn_maxfan=4 *) reg [log2x(DEPTH)-1:0] r_write_addr;
  (* syn_maxfan=4 *) reg [WIDTH-1:0] r_write_data;
  (* syn_maxfan=4 *) reg r_write_en;
  
  (* syn_ramstyle = "block_ram" *) reg [WIDTH-1:0] myram[DEPTH-1:0];
  reg [WIDTH-1:0] myram_do;

  always_ff @(posedge gclk.clk)
  begin
//    r_read_addr <= read_addr;
    r_write_addr <= write_addr;
    r_write_data <= write_data;
    r_write_en <= write_en;
  end
  
    
  always_ff @(posedge gclk.clk)
  begin
  //  read_data <= myram[r_read_addr];
    myram_do <= myram[read_addr];
    read_data <= myram_do;
    if(r_write_en)
      myram[r_write_addr] <= r_write_data;
  end
    
endmodule


// a queue with one read port and one write port.
module replay_fifo #(parameter DEPTH=NTHREAD, parameter WIDTH=NTHREADIDMSB+1)
  (input iu_clk_type gclk, input bit rst, input bit enq,
   input bit[WIDTH-1:0] enq_data, input bit deq,
   output bit[WIDTH-1:0] head, output bit empty, output bit full);
   
   parameter NDEPTHMSB = log2x(DEPTH)-1;
   bit might_be_empty;
   (* syn_maxfan = 4 *) bit[NDEPTHMSB:0] head_ptr, tail_ptr;
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
      
      if(deq != enq)
      	might_be_empty <= deq;

    end

  end
  
  //synthesis translate_off
  always @(posedge gclk.clk) begin
    //if(enq | deq) begin
    //  $display("@%t: %m count %d %s %d",$time,tail_ptr-head_ptr,enq?"enq":"deq",enq_data);
    //end
  end
  
  bit [NDEPTHMSB:0] count0,idx0,idx1;
  bit [NDEPTHMSB+1:0] count;
  always_comb begin
    count0 = tail_ptr-head_ptr;
    count = {full,count0};
  end
  always_ff @(posedge gclk.clk) begin
    if(!rst && count > 0) begin
      for(int i = 0; i < count; i++) begin
        for(int j = i+1; j < count; j++) begin
          idx0 = head_ptr+i;
          idx1 = head_ptr+j;
          if(ram[idx0] == ram[idx1]) begin
            $display("@%t: %m: duplicate value %d (idx %d %d, head %d, tail %d, count %d)",$time,ram[idx0],idx0,idx1,head_ptr,tail_ptr,count);
            $stop(0);
          end
        end
      end
    end
  end
  
  property no_overflow;
    @(posedge(gclk.clk))
      disable iff (rst)
      ~(full & enq);
  endproperty
  property no_underflow;
    @(posedge(gclk.clk))
      disable iff (rst)
      ~(empty & deq);
  endproperty
  assert property(no_overflow) else begin $display("@%t %m overflowed!!",$time); $stop(0); end
  assert property(no_underflow) else begin $display("@%t %m underflowed!!",$time); $stop(0); end
  //synthesis translate_on

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