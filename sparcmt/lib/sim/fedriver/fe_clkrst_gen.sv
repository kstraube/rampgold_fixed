//---------------------------------------------------------------------------   
// File:        clkrst_gen.v
// Author:      Zhangxi Tan
// Description: Generate clk and rst.	
//---------------------------------------------------------------------------

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libtech::*;
import libfedriver::*;
`else
`include "libfedriver.sv"
`include "libiu.sv"
`endif

module fedriver_clkrst_gen #(parameter differential = 1,
`ifndef SYNP94
  parameter fpgatech_type fpgatech = xilinx_virtex5,
`else	
  parameter fpgatech = 1,
`endif	
  parameter BOARDSEL = 1

) (input bit clkin_p, input bit clkin_n, input bit rstin, output fedriver_clk_type fe_clk, output fe_rst);
	bit			dcm_locked;		//DCM is locked
	
  bit   clkin;

	bit			clk;			//main clk
	bit			clk2x;			//clk2x
	
  //clock input buffer
  clk_inb #(.differential(differential), .fpgatech(fpgatech)) gen_clkinp(.clk_p(clkin_p), .clk_n(clkin_n), .clk(clkin));

	cpu_clkgen #(.fpgatech(fpgatech), .CLKMUL(CLKMUL), .CLKDIV(CLKDIV), .CLKIN_PERIOD(CLKIN_PERIOD)) gen_feclk (
		.clkin,
		.rstin,
		.clk,
		.clk2x,		
		.locked(dcm_locked));
	
	assign fe_rst = rstin | ~dcm_locked;
	assign fe_clk.clk = clk;
	assign fe_clk.clk2x = clk2x;
	
endmodule