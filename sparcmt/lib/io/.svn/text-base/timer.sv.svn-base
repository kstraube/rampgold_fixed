//---------------------------------------------------------------------------   
// File:        timer.sv
// Author:      Zhangxi Tan
// Description: A simple timer with interrupt
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps
`ifndef SYNP94
import libconf::*;
import libiu::*;
import libio::*;
`else
`include "../cpu/libiu.sv"
`include "libio.sv"
`endif


//address map:
// Write to any address will reload the counter with the enable bit

module timer #(parameter NWIDTH=24, parameter bit [3:0] addrmask = 4'b0 ) (input iu_clk_type gclk, input bit rst, 
             // CPU interface
             input  io_bus_in_type       bus_in,
             input   bit                 tick,
             // IO bus device interface
//             output  bit                 bus_owner,           //@M2 
             output  bit                 irq                  //@M2
            );
            
          bit [NWIDTH-1:0]      target_cycle;
          
          (* syn_ramstyle = "select_ram" *) bit [NWIDTH:0]  preload_ram[0:NTHREAD-1];   //The highest bit is 'interrupt enable' 
          bit                                        timer_sel;
          (* syn_maxfan = 16 *) bit                  preload_we;
          (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0] preload_waddr;
          bit [NWIDTH:0]  preload_dout, preload_din;

          always_ff @(posedge gclk.clk) begin
              if (rst) target_cycle <= '0;
              else
                if (tick) target_cycle <= target_cycle+1;                
                  
              preload_waddr <= bus_in.tid;
              timer_sel <= (bus_in.addr[IO_AWIDTH-1 : IO_AWIDTH-4] == addrmask) ? '1 : '0;
          end          
           
          always_comb begin
           irq = preload_dout[NWIDTH] & ~(|((preload_dout[0 +: NWIDTH] & target_cycle[0 +: NWIDTH]) ^ preload_dout[0 +: NWIDTH]));
           
           preload_we = timer_sel & bus_in.rw & bus_in.en | rst;
           preload_din = bus_in.wdata[NWIDTH:0];
           if (rst) preload_din[NWIDTH] = '0;
          end
          
          //preload ram
          always_ff @(posedge gclk.clk) if (preload_we) preload_ram[preload_waddr] <= preload_din;
          always_ff @(posedge gclk.clk) preload_dout <= preload_ram[bus_in.tid];
endmodule