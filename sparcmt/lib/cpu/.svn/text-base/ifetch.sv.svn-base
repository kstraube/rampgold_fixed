//---------------------------------------------------------------------------   
// File:        ifetch.v
// Author:      Zhangxi Tan
// Description: instruction fetch, thread selection
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libdebug::*;
import libiu::*;
import libopcodes::*;
import libucode::*;
import libmmu::*;
import libcache::*;
import libstd::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`endif

typedef struct packed{
	bit	pc;	         //parity bit for pc
	bit	npc;	        //parity bit for npc
	bit	archr;	      //parity bit for psr & wim
	bit	ts;	         //parity bit for thread state
	bit y;           //parity bit for y, used by decode only
} spr_parity_type; 

//use memory compiler first, should be mapped to several RAM64M on Xilinx V5
//outputs are registered
module spr_ram (input iu_clk_type gclk, input bit rst, input bit [NTHREADIDMSB:0] rthid, input bit [NTHREADIDMSB:0] wthid, input spr_commit_type spri, output spr_commit_type spro, input spr_parity_type spre, output spr_parity_type sprd);	
  //structures for ram
  typedef struct packed {
        psr_reg_type         psr;        //psr
        bit [NWIN-1:0]	      wim;		      //wim	
        bit                  parity;
  }ram_archr_type;
  
  typedef struct packed {
        bit			               run;		           //run bit, part of WE
        bit                  icmiss;          //icache miss bit
        bit 			              replay;		        //replay bit
        bit			               annul;	          //annul bit (annulled by bicc, but increment PC)
        bit			               ucmode;		        //micro code mode
        bit [NUPCMSB:0]      upc;		           //microcode pc
        bit [FLUSHIDXMSB:0]  flushidx;        //flush index	
        bit                  parity;
  }ram_ts_type;

	(* syn_ramstyle = "select_ram" *) bit [29+LUTRAMPROT:0]		            pc[0:NTHREAD-1];	   //mapped to 8 RAM64M for pc
  (* syn_ramstyle = "select_ram" *) bit [29+LUTRAMPROT:0]		            npc[0:NTHREAD-1];	  //mapped to 8 RAM64M for npc

  (* syn_ramstyle = "select_ram" *) y_reg_type		                       y[0:NTHREAD-1];	    //mapped to 8 RAM64M for y
 
  //(* syn_ramstyle = "select_ram" *) bit [11+NWINMSB+NWIN+LUTRAMPROT:0]	            archr[0:NTHREAD-1];	//mapped to 4 RAM64M for psr, wim
  //(* syn_ramstyle = "select_ram" *) bit [6+FLUSHIDXMSB+NUPCMSB+LUTRAMPROT:0]		     ts[0:NTHREAD-1];	   //mapped to 2 RAM64M for thread_state
  (* syn_ramstyle = "select_ram" *) ram_archr_type	                    archr[0:NTHREAD-1];	//mapped to 4 RAM64M for psr, wim  
  (* syn_ramstyle = "select_ram" *) ram_ts_type		                      ts[0:NTHREAD-1];	   //mapped to 2 RAM64M for thread_state  
	
	bit [NTHREADIDMSB:0]	              addr;		             //ram address	
	//bit	wren;				//general wren for lutram

  //tribute to the stupid synplify memory compiler
  bit [29+LUTRAMPROT:0]		                        w_pc;	  
  bit [29+LUTRAMPROT:0]		                        w_npc;	 
  y_reg_type		                                   w_y;	 
  
  //bit [11+NWINMSB+NWIN+LUTRAMPROT:0]	            w_archr;	
  //bit [6+FLUSHIDXMSB+NUPCMSB+LUTRAMPROT:0]		     w_ts;	
  ram_archr_type                                 w_archr;
  ram_ts_type                                    w_ts;
	
	//RAM DO registers 
	spr_commit_type 	sprdo;
	spr_parity_type		parity; 

	//assign addr <=  (rst | !wren) ? rthid : wthid;
	assign addr =  (gclk.ce) ? wthid : rthid;
	
	assign spro = sprdo;
	assign sprd = parity;			

  //memory read port
  assign w_pc    = pc[addr];
  assign w_npc   = npc[addr];
  assign w_y     = y[addr];
  assign w_archr = archr[addr];
  assign w_ts    = ts[addr];
  
	//clk 1x
	always_ff @(negedge gclk.clk) begin						
	//read
    /*
		sprdo.pc               <= pc[addr][29:0];
		sprdo.npc              <= npc[addr][29:0];
    sprdo.y                <= y[addr];
		{sprdo.wim, sprdo.psr} <= archr[addr][11+NWINMSB+NWIN:0];
		// sprdo.psr <=			archr[addr][0 +: $bits(spri.psr)];
    // sprdo.wim <=			archr[addr][$bits(spri.psr) +: NWIN];
    
    {sprdo.icmiss, sprdo.replay, sprdo.annul, sprdo.ucmode, sprdo.upc}  <=  ts[addr][4+NUPCMSB:0];
    */
    
    sprdo.pc               <= w_pc[29:0];
    sprdo.npc              <= w_npc[29:0];
    sprdo.y                <= w_y;
    //{sprdo.wim, sprdo.psr} <= w_archr;
    //{sprdo.icmiss, sprdo.replay, sprdo.annul, sprdo.ucmode, sprdo.upc}  <=  w_ts[4+NUPCMSB:0];

    sprdo.wim <= w_archr.wim;
    sprdo.psr <= w_archr.psr;

    sprdo.icmiss <= w_ts.icmiss;
    sprdo.replay <= w_ts.replay;
    sprdo.annul  <= w_ts.annul; 
    sprdo.ucmode <= w_ts.ucmode;
    sprdo.upc    <= w_ts.upc;
    
    //if (rst) sprdo.run <= '0; else sprdo.run <= w_ts[5+NUPCMSB];
    //sprdo.flushidx <= w_ts[5+NUPCMSB+1 +: FLUSHIDXMSB+1];
		if (rst) sprdo.run <= '0; else sprdo.run <= w_ts.run;
    sprdo.flushidx <= w_ts.flushidx;

		
		if (LUTRAMPROT) begin		//read out parities
			parity.pc    <= w_pc[29+LUTRAMPROT]; 
			parity.npc   <= w_npc[29+LUTRAMPROT];
//			parity.archr <= w_archr[11+NWINMSB+NWIN+LUTRAMPROT];
//			parity.ts    <= w_ts[6+FLUSHIDXMSB+NUPCMSB+LUTRAMPROT];
      parity.archr <= w_archr.parity;
      parity.ts    <= w_ts.parity;
			parity.y     <= w_y.parity;
		end
		else
		  parity  <= '{0, 0, 0, 0, 0};  		
	end


	//RAMs
	always_ff @(posedge gclk.clk) begin		//write data at the posedge of clk 
		//wren <= (rst == 1'b1) ? '1 : !wren;			
		// RAMs
		if (spri.pc_we)		//write pc <- 0 during reset
			pc[addr] <= (LUTRAMPROT == 0)? spri.pc : {spre.pc, spri.pc};
	
		if (spri.npc_we)		//write npc <- 4 during reset
			npc[addr] <= (LUTRAMPROT == 0)? spri.npc : {spre.npc, spri.npc};

		if (spri.archr_we) begin
//			archr[addr] <= (LUTRAMPROT == 0)? {spri.wim, spri.psr} : {spre.archr, spri.wim, spri.psr};		
			archr[addr].wim <= spri.wim;
			archr[addr].psr <= spri.psr;
			archr[addr].parity = (LUTRAMPROT)? spre.archr : '0;
		end

    if ( spri.archr_we)
      y[addr] <= spri.y;
      
	//	if (spri.run | rst) begin
	  if (spri.ts_we) begin
			//ts[addr] <= (LUTRAMPROT == 0)? {spri.flushidx, spri.run, spri.icmiss, spri.replay, spri.annul, spri.ucmode, spri.upc} : {spre.ts, spri.flushidx, spri.run, spri.icmiss, spri.replay, spri.annul, spri.ucmode, spri.upc};
			ts[addr].flushidx <= spri.flushidx;
			ts[addr].run      <= spri.run;
			ts[addr].icmiss   <= spri.icmiss;
			ts[addr].replay   <= spri.replay;
			ts[addr].annul    <= spri.annul;
			ts[addr].ucmode   <= spri.ucmode;
			ts[addr].upc      <= spri.upc;
			ts[addr].parity   <= (LUTRAMPROT) ? spre.ts : '0;
		end	
	end

	
endmodule 


function automatic bit is_flush(thread_state_type ts);
  if (ts.ucmode == 1 && ts.upc == UPC_FLUSH)
    return '1;
  else
    return '0;    
endfunction

module fetch_stage(input iu_clk_type gclk, input rst, 
		input 	 commit_reg_type 	     comr, 
		output 	decode_reg_type 	     der, 
		output 	immu_iu_in_type 	     immu_if_in, 
		output 	icache_if_in_type 	   icache_if_in, 
		input 	 icache_data_out_type 	icache_if_out, 
		output 	bit			                luterr);	
		
	spr_parity_type		    spre, sprd;   //parity encode/decode
	spr_commit_type 	    spro;		       //read result for spr register
	bit [NTHREADIDMSB:0]	rthid, wthid;	//read thread id (power of 2)
	
	typedef struct {
		bit [NTHREADIDMSB:0]	tid;
		bit			               tid_parity;	
		spr_commit_type		    spr;
		spr_parity_type		    parity;
		microcode_out_type	  uco;
	}ifetch_delay_reg_type;
	
	ifetch_delay_reg_type	 delr;			                //pipeline register	
	
	bit			                 parity_error;	          //parity error
	bit			                 mmucache_valid;		       //mmu, cache_request is valid; 

	bit			                 tid_parity;

	microcode_out_type	    uco;                    //microcode output

	decode_reg_type		derin;
	//spr is written in the second half cycle, because of parity encoding
	
	//generate parity bits if lutram protection is turned on	
	always_comb begin
		if (LUTRAMPROT)	begin	
			//encoding parity bits	
			spre.pc      = ^comr.spr.pc;
			spre.npc     = ^comr.spr.npc;
			spre.archr   = ^{comr.spr.psr, comr.spr.wim};
			spre.ts      = ^{comr.spr.run, comr.spr.icmiss, comr.spr.replay, comr.spr.annul, comr.spr.ucmode, comr.spr.upc};
			spre.y       = '0;       //no use
			//decoding
			//parity_error = delr.parity.pc | delr.parity.npc | delr.parity.archr | delr.parity.ts | delr.parity.y;						
			parity_error = |delr.parity ;
		end
		else begin
		  spre = '{0, 0, 0, 0, 0};
		  parity_error = '0;
		end

		//MMU/cache result relay stage
		derin.ts.tid        = delr.tid;
		derin.ts.tid_parity = delr.tid_parity;
		
		derin.ts.run        = delr.spr.run;
		derin.ts.replay     = delr.spr.replay;
		derin.ts.icmiss     = delr.spr.icmiss;
		derin.ts.annul      = delr.spr.annul;
		derin.ts.ucmode     = delr.spr.ucmode;
		derin.ts.psr        = delr.spr.psr;
		derin.ts.y          = delr.spr.y;
		derin.ts.wim        = delr.spr.wim;
		derin.ts.pc         = delr.spr.pc;
		derin.ts.npc        = delr.spr.npc;
		
		derin.ts.upc        = delr.spr.upc;
		derin.ts.uend       = delr.uco.uend;
		
		derin.ts.flushidx   = delr.spr.flushidx;
		
		//don't care part
		derin.ts.dma_mode   = '0;
		derin.ts.dma_state  = debug_dma_iu_state_none;
		
		//decode microcode indirection bits 
		derin.ts.rdmask = delr.spr.ucmode & delr.uco.inst[UCIPOS_RD]  & ~delr.uco.cwp_rd;
		derin.rs1mask   = delr.spr.ucmode & delr.uco.inst[UCIPOS_RS1] & ~delr.uco.cwp_rs1;
		derin.rs2mask   = delr.spr.ucmode & delr.uco.inst[UCIPOS_RS2] & ~delr.uco.inst[13];		
		derin.cwp_rs1   = delr.uco.cwp_rs1;
		derin.cwp_rd    = delr.uco.cwp_rd;
				
		//derin.ts.inst   = {icache_if_out[7:0], icache_if_out[15:8], icache_if_out[23:16], icache_if_out[31:24]};		//input from icache, big endian		
	  derin.ts.inst   = ldst_big_endian(icache_if_out);
		derin.microinst = delr.uco.inst;	//microcode  
		
		//does nothing (will be optimized away)
		derin.ts.ldst_a = '0;
		derin.ts.asi    = '0;
	end

  assign tid_parity = (LUTRAMPROT)? ^rthid : '0;

	always_ff @(posedge gclk.clk) begin		
		rthid <= rthid + 1;	//static thread scheduling goes here

		//relay registers for MMU/cache compare stage
		delr.tid        <= rthid;
		delr.tid_parity <= tid_parity;
		delr.spr        <= spro;
		delr.uco        <= uco;		//microcode output

		if (LUTRAMPROT)	begin 
			//parity decoding 
			delr.parity.pc    <= ^spro.pc ^ sprd.pc;
			delr.parity.npc   <= ^spro.npc ^ sprd.npc;
			delr.parity.archr <= ^{spro.psr, spro.wim} ^ sprd.archr;
			delr.parity.ts    <= ^{spro.flushidx, spro.run, spro.icmiss, spro.replay, spro.annul, spro.ucmode, spro.upc} ^ sprd.ts;
			delr.parity.y     <= ^spro.y.y ^ sprd.y;           //can be written as ^spro.y
		end
		else begin
			delr.parity    <= '{0, 0, 0, 0, 0};
		end
		
		//decode pipeline register
		der <= derin;
	end
	
	//Global signals	
	assign luterr = parity_error; 

	assign wthid = comr.regf.ph1_addr[NREGADDRMSB:NREGADDRMSB-NTHREADIDMSB];	//recover write thread id

	generate
		if (SPRBRAM == 0)			//BRAM spr is not supported currently
			spr_ram spreg(.spri(comr.spr), .*);
	endgenerate

	//Is mmu/cache request valid	
	//assign mmucache_valid = spro.run & !spro.ucmode & !spro.annul_trap;
	//assign mmucache_valid = spro.run & !rst;
  assign mmucache_valid = spro.run & ~spro.dma_mode;       //don't need rst here? immu won't do anything during global reset

	//I-MMU input signals		
	assign immu_if_in.tid          = rthid;
	assign immu_if_in.vpc          = spro.pc;
	assign immu_if_in.valid        = mmucache_valid;
	assign immu_if_in.su           = spro.psr.s;
	assign immu_if_in.replay       = spro.replay;
	assign immu_if_in.vpc_parity   = sprd.pc;
  //second cycle IF input
  assign immu_if_in.iflush     = is_flush(derin.ts);
  assign immu_if_in.flushidx   = derin.ts.flushidx;


	//I$ read request
	assign icache_if_in.tid        = rthid;
	assign	icache_if_in.tid_parity = tid_parity;
	assign	icache_if_in.vpc        = spro.pc;
	assign	icache_if_in.valid      = mmucache_valid;
	assign	icache_if_in.replay     = spro.replay;
			
	//microcode rom
	microcode_rom ucode(.upc(spro.upc), .uco); 	
endmodule
