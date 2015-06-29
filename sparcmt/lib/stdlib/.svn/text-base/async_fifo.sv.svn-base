//------------------------------------------------------------------------------   
// File:        async_fifo.sv
// Author:      Zhangxi Tan
// Description: Asynch fifo implemenations.
//------------------------------------------------------------------------------  
`timescale 1ns / 1ps

//one entry async fifo
module async_fifo_one #(parameter DWIDTH=1)(input  bit rst,
					     input  bit [DWIDTH-1:0] din,
					     input  bit we,
					     input  bit wclk,
					     input  bit rclk,
					     input  bit re,
					     output bit	empty,
					     output bit full,
					     output bit [DWIDTH-1:0] dout);
	//data storage 
	bit [DWIDTH-1:0]	fifo_data;
	
	//read/write counter (gray code)
	bit			wcnt, rcnt;
	
	//cross clock domain registers
	(* syn_srlstyle="registers" *) bit [2:0]	w2r, r2w;
	
	
	//write clock domain
	always_ff @(posedge wclk or posedge rst) begin
		if (rst) 
			wcnt <= '0;
		else begin
			if (we) wcnt <=	~wcnt;
		end	
		
//		if (we) fifo_data <= din;
		
//		r2w[2:0] <= {r2w[1:0], rcnt};		//rcnt -> r2w[0] is a mcp
	end
	
	always_ff @(posedge wclk) begin
		if (we) fifo_data <= din;
		
		r2w[2:0] <= {r2w[1:0], rcnt};		//rcnt -> r2w[0] is a mcp
	end
	
	assign full = r2w[2] ^ wcnt;
	
	//read clock domain
	always_ff @(posedge rclk or posedge rst) begin
		if (rst) 
			rcnt <= '0;
		else begin
			if (re) rcnt <= ~rcnt;
		end
		
//		w2r[2:0] <= {w2r[1:0], wcnt};		//wcnt -> w2r[0] is a mcp
	end
	
	always_ff @(posedge rclk)
		w2r[2:0] <= {w2r[1:0], wcnt};		//wcnt -> w2r[0] is a mcp

	assign dout = fifo_data;			//fifo_data -> dout is a one rclk cycle path
	assign empty = ~(w2r[2] ^ rcnt);
endmodule 