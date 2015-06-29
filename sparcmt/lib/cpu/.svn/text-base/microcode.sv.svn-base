//------------------------------------------------------------------------------   
// File:        microcode.v
// Author:      Zhangxi Tan
// Description: micro pc map and microcode implementation
//------------------------------------------------------------------------------  
`timescale 1ns / 1ps

`ifndef SYNP94
import libucode::*;
import libopcodes::*;
`else
`include "libucode.sv"
`include "opcodes.sv"
`endif

//implemented using LUT

//cwp_rs1 bit will be optimized in current implementation
module microcode_rom(input bit [NUPCMSB:0] upc, output microcode_out_type uco);	
	always_comb begin
		unique case(upc)
		//----------trap---------
		0: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, REGADDR_TBR | UCI_MASK, IAND, REGADDR_TBR | UCI_MASK, 1'b1, 13'b1000000000000}; end			//and tbr, tbr, 0xfffff000
		1: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, REGADDR_TBR | UCI_MASK, IADD, REGADDR_SCRATCH_0 | UCI_MASK, 1'b0, 8'b0, REGADDR_TBR | UCI_MASK}; end	//add tbr, tbr, scratch (tt)
		2: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '1; uco.inst = {FMT3, 5'd17, JMPL, REGADDR_TBR | UCI_MASK, 1'b1, 13'b0}; end	//jmpl r17, TBR, 0		put PC -> r17 and TBR->npc 
		3: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT2, 1'b0, BN, 3'b010, 22'h0}; end	//BN without annul (NOP), npc->pc, npc->npc + 4
		//----------ST*-------
		4: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, ST, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	  //st rd, scratch_0, 0
		//----------STB*-------
		5: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STB, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	 //stb rd, scratch_0, 0
		//----------STH*-------
		6: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STH, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	 //stb rd, scratch_0, 0
		//----------STD*-------
		7: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, ST, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	  //st rd, scratch_0, 0
		8: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STD, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'd4 }; end	 //std rd, scratch_0, 4
		//----------SWAP*-------
		9: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, ST, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0}; end	   //st rd, scratch_0, 0
		10: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, 5'b0, IADD, REGADDR_SCRATCH_1 | UCI_MASK, 1'b1, 13'b0}; end //add rd, scratch_1, 0
		//----------LDSTUB*-------
		11: begin uco.uend = '0; uco.cwp_rs1 = '1; uco.cwp_rd = '0; uco.inst = {FMT3, REGADDR_SCRATCH_1 | UCI_MASK, IADD, 5'b0, 1'b1, 13'hff}; end	                      //add scratch_1, g0, 0xff 
		12: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, REGADDR_SCRATCH_1 | UCI_MASK, STB, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0};	end	//stb scratch_1, scratch_0 (paddr), 0	
		//----------FLUSH---------
		13: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, 5'b0, FLUSH, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0}; end //flush scratch_0
		//----------WRTBR---------  
		14: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, REGADDR_TBR | UCI_MASK, IAND, REGADDR_TBR | UCI_MASK, 1'b1, 13'hff0}; end			//and tbr, tbr, 0xff0
		15: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {FMT3, REGADDR_TBR | UCI_MASK, IADD, REGADDR_SCRATCH_0 | UCI_MASK, 1'b0, 8'b0, REGADDR_TBR | UCI_MASK}; end	//add tbr, tbr, scratch (tba)
		//----------STF-----------
		16: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STF, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	//st rd, scratch, 0  
    // ---------STDF----------
		17: begin uco.uend = '0; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STF, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	//st rd, scratch, 0
		18: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STDF, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'd4 }; end	//std rd, scratch, 4
    // ---------STFSR------
		19: begin uco.uend = '1; uco.cwp_rs1 = '0; uco.cwp_rd = '0; uco.inst = {LDST, 5'b0, STFSR, REGADDR_SCRATCH_0 | UCI_MASK, 1'b1, 13'b0 }; end	//st rd, scratch, 0		 
		 
`ifndef SYNP94
		default : uco = {'0,'0,'0,'0};
`else
		default : uco = {1'b0,1'b0,1'b0,32'd0};
`endif
		endcase
	end
endmodule