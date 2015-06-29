//-------------------------------------------------------------------------------------------------------  
// File:        top_1P_bram_dma_ps_sim.v
// Author:      Zhangxi Tan
// Description: Top level simulation file for post-synthesis.
//-------------------------------------------------------------------------------------------------------   
`timescale 1ns / 1ps

import libconf::*;
import libiu::*;
import libio::*;

module sim_top;

parameter clkperiod = 2.5;   //200 MHz

bit clk=0;
bit rst;
bit cpurst;

//IO interface
io_bus_out_type      io_in;
io_bus_in_type       io_out;

//wires for disasm
iu_clk_type	    gclk;	      //global clock and clock enable
bit		           rst_out;		  //reset
xc_reg_type 		  xcr;
bit             dcache_replay;


default clocking main_clk @(posedge clk);
endclocking

initial begin
  forever #clkperiod clk = ~clk;
end

initial begin
  rst 	 = '0;
  cpurst = '0;
  io_in.retry = '0;
  io_in.irl   = '0;
  io_in.rdata = '0;

//  ##10;
//  rst = '0;
  
  ##200;
  rst = '1;
  
  
  ##200;
  cpurst = '1;
  
  ##10;
  cpurst = '0;
end

fpga_top sim(.clkin_p(clk), 
            .clkin_n(~clk),
            .rstin(rst),
            .cpurst, 
            .error_led(),
            .done_led(),
            //connect to disasm
            .xc_tid(xcr.ts.tid),
            .xc_run(xcr.ts.run),
            .xc_inst(xcr.ts.inst),
            .xc_pc(xcr.ts.pc),
            .xc_icmiss(xcr.ts.icmiss),
            .xc_replay(xcr.ts.replay),
            .xc_annul(xcr.ts.annul),
            .xc_ucmode(xcr.ts.ucmode),
            .xc_upc(xcr.ts.upc),
            .xc_dmamode(xcr.ts.dma_mode),
            .dcache_replay,
            .rst_out,
            .clk_out(gclk.clk)                    
            );

disassembler gen_disasm(.*, .rst(rst_out));

endmodule
