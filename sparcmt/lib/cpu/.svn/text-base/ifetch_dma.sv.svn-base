//---------------------------------------------------------------------------   
// File:        ifetch_dma.v
// Author:      Zhangxi Tan
// Description: instruction fetch, thread selection, with init dma support
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libfp::*;
import libopcodes::*;
import libucode::*;
import libmmu::*;
import libcache::*;
import libstd::*;
import libdebug::*;
import libtm::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
//`include "libdebug.sv"
`include "../tm/libtm.sv"
`endif

typedef struct packed{
	bit	pc;	         //parity bit for pc
	bit	npc;	        //parity bit for npc
	bit	archr;	      //parity bit for psr & fsr & wim
	bit	ts;	         //parity bit for thread state
	bit y;           //parity bit for y, used by decode only
	bit psr;         //parity bit for psr
} spr_parity_type; 

//use memory compiler first, should be mapped to several RAM64M on Xilinx V5
//outputs are registered
(* syn_maxfan = 16*) module spr_ram (input iu_clk_type gclk, input bit rst, input tm2cpu_token_type tm2cpu, input bit [NTHREADIDMSB:0] wthid, input spr_commit_type spri, output spr_commit_type spro, input spr_parity_type spre, output spr_parity_type sprd);	
  //structures for ram
  typedef struct packed {
  	bit	  	         s;	  //supervisor mode
	 bit	  	         ps;	 //previous supervisor mode
	 bit	  	         et;	 //enable trap
	 bit [NWINMSB:0]	cwp;	//current window pointer	
	 bit             parity;
  }ram_psr_type;
  
  typedef struct packed {
//        psr_reg_type         psr;        //psr
  	     struct packed {
  	       alu_flag_type 	 icc;	//alu flags
	        bit             ef;  //enable floating point
	        bit [3:0] 	     pil;	//processor interrupt level
        }psr;
        
        fsr_reg_type         fsr;        //fsr
        bit [NWIN-1:0]	      wim;		      //wim	
        bit                  parity;
  }ram_archr_type;
  
  typedef struct packed {
//      bit			               run;		           //run bit, part of WE
        bit                  icmiss;          //icache miss bit
        bit 			              replay;		        //replay bit
        bit			               annul;	          //annul bit (annulled by bicc, but increment PC)
        bit			               ucmode;		        //micro code mode
        bit                  dma_mode;        //dma mode
        bit [NUPCMSB:0]      upc;		           //microcode pc
        bit [FLUSHIDXMSB:0]  flushidx;        //flush index	
        bit                  parity;
  }ram_ts_type;

	(* syn_ramstyle = "select_ram" *) bit [29+LUTRAMPROT:0]		            pc[0:NTHREAD-1];	   //mapped to 8 RAM64M for pc
  (* syn_ramstyle = "select_ram" *) bit [29+LUTRAMPROT:0]		            npc[0:NTHREAD-1];	  //mapped to 8 RAM64M for npc

  (* syn_ramstyle = "select_ram" *) y_reg_type		                       y[0:NTHREAD-1];	    //mapped to 8 RAM64M for y
 
  (* syn_ramstyle = "select_ram" *) ram_archr_type	                    archr[0:NTHREAD-1];	
  (* syn_ramstyle = "select_ram" *) ram_psr_type	                      psr[0:NTHREAD-1];	 
  (* syn_ramstyle = "select_ram" *) ram_ts_type		                      ts[0:NTHREAD-1];	   //mapped to 2 RAM64M for thread_state  

	
  (* syn_maxfan = 16*)  bit [NTHREADIDMSB:0]	              addr;		             //ram address	

  //tribute to the stupid synplify memory compiler
  bit [29+LUTRAMPROT:0]		                        w_pc;	  
  bit [29+LUTRAMPROT:0]		                        w_npc;	 
  y_reg_type		                                   w_y;	 
  ram_archr_type                                 w_archr;
  psr_reg_type                                   w_psr;
  ram_ts_type                                    w_ts;
  
  bit                                            w_psr_parity;

	
	//RAM DO registers 
	spr_commit_type 	sprdo;
	spr_parity_type		parity; 

	assign addr =  (gclk.ce) ? wthid : tm2cpu.tid;
	
	assign spro = sprdo;
	assign sprd = parity;			

  //memory read port
  assign w_pc    = pc[addr];
  assign w_npc   = npc[addr];
  assign w_y     = y[addr];
  assign w_archr = archr[addr];
  assign w_ts    = ts[addr];
  
  assign w_psr.s   = psr[addr].s;
  assign w_psr.ps  = psr[addr].ps;
  assign w_psr.et  = psr[addr].et;
  assign w_psr.cwp = psr[addr].cwp;  
  assign w_psr_parity = psr[addr].parity;
  assign w_psr.icc = archr[addr].psr.icc;
  assign w_psr.pil = archr[addr].psr.pil;
  assign w_psr.ef  = archr[addr].psr.ef;
  
  

  
	//clk 1x
//	always_ff @(negedge gclk.clk) begin						
	always_ff @(posedge gclk.clk2x) begin
	if (!gclk.ce) begin
    
    sprdo.pc               <= w_pc;
    sprdo.npc              <= w_npc;
    sprdo.y                <= w_y;
    sprdo.wim <= w_archr.wim;
//    sprdo.psr <= w_archr.psr;
    sprdo.psr <= w_psr;
    sprdo.fsr <= w_archr.fsr;

    sprdo.icmiss <= w_ts.icmiss;
    sprdo.replay <= w_ts.replay;
    sprdo.annul  <= w_ts.annul; 
    sprdo.ucmode <= w_ts.ucmode;
    sprdo.upc    <= w_ts.upc;    
    
    //if (rst) sprdo.run <= '0; else sprdo.run <= w_ts[5+NUPCMSB];
    //sprdo.flushidx <= w_ts[5+NUPCMSB+1 +: FLUSHIDXMSB+1];
    //sprdo.dma_mode <= w_ts[7+FLUSHIDXMSB+NUPCMSB+LUTRAMPROT];
    if (rst) sprdo.run <= '0; else sprdo.run <= tm2cpu.run;
    sprdo.valid <= tm2cpu.valid;
    sprdo.flushidx <= w_ts.flushidx;
    sprdo.dma_mode <= w_ts.dma_mode;

			
		if (LUTRAMPROT) begin		//read out parities
			parity.pc    <= w_pc[29+LUTRAMPROT]; 
			parity.npc   <= w_npc[29+LUTRAMPROT];
			//parity.archr <= w_archr[11+NWINMSB+NWIN+LUTRAMPROT];
			//parity.ts    <= w_ts[7+FLUSHIDXMSB+NUPCMSB+LUTRAMPROT];
			parity.archr <= w_archr.parity;
      parity.ts    <= w_ts.parity;
			parity.y     <= w_y.parity;
			parity.psr   <= w_psr_parity;
		end
		else
		  parity  <= '{0, 0, 0, 0, 0, 0};  
		
		//if (rst) sprdo.run = '0;
	end
	end

	//RAMs
//	always_ff @(posedge gclk.clk) begin		//write data at the posedge of clk 
	always_ff @(posedge gclk.clk2x) begin		//write data at the posedge of clk 
	 if (gclk.ce) begin
		// RAMs
		if (spri.pc_we)		//write pc <- 0 during reset
			pc[addr] <= (LUTRAMPROT == 0)? spri.pc : {spre.pc, spri.pc};
	
		if (spri.npc_we)		//write npc <- 4 during reset
			npc[addr] <= (LUTRAMPROT == 0)? spri.npc : {spre.npc, spri.npc};

		if (spri.archr_we) begin
			archr[addr].wim <= spri.wim;
      archr[addr].psr.icc <= spri.psr.icc;
      archr[addr].psr.pil <= spri.psr.pil;
      archr[addr].psr.ef  <= spri.psr.ef;
      archr[addr].fsr <= spri.fsr;
      archr[addr].parity = (LUTRAMPROT)? spre.archr : '0;
		end

    if ( spri.archr_we)
      y[addr] <= spri.y;
      
    if (spri.psr_we) begin
      psr[addr].s <= spri.psr.s;
      psr[addr].ps <= spri.psr.ps;
      psr[addr].et <= spri.psr.et;
      psr[addr].cwp <= spri.psr.cwp;
      psr[addr].parity <= (LUTRAMPROT) ? spre.psr : '0;
    end
      
    if (spri.ts_we) begin
			//ts[addr] <= (LUTRAMPROT == 0)? {spri.dma_mode, spri.flushidx, spri.run, spri.icmiss, spri.replay, spri.annul, spri.ucmode, spri.upc} : {spre.ts, spri.dma_mode, spri.flushidx, spri.run, spri.icmiss, spri.replay, spri.annul, spri.ucmode, spri.upc};
      ts[addr].dma_mode <= spri.dma_mode;
			ts[addr].flushidx <= spri.flushidx;
//      ts[addr].run      <= spri.run;
      ts[addr].icmiss   <= spri.icmiss;
      ts[addr].replay   <= spri.replay;
      ts[addr].annul    <= spri.annul;
      ts[addr].ucmode   <= spri.ucmode;
      ts[addr].upc      <= spri.upc;
      ts[addr].parity   <= (LUTRAMPROT) ? spre.ts : '0;
		end
	end
	end

	
endmodule 


function automatic bit is_flush(thread_state_type ts);
  if (ts.ucmode == 1 && ts.upc == UPC_FLUSH)
    return '1;
  else
    return '0;    
endfunction

module fetch_stage_dma #(parameter bit newsch = 1'b0) (input iu_clk_type gclk, input rst, 
		input 	 commit_reg_type 	     comr, 
		output 	decode_reg_type 	     der, 
		output 	immu_iu_in_type 	     immu_if_in, 
		output 	icache_if_in_type 	   icache_if_in, 
		input 	 icache_data_out_type 	icache_if_out,         
		output 	bit			                luterr,
		//dma interface
		output  bit [NTHREADIDMSB:0]      dma_rtid,
		input   debug_dma_out_type	       dma2iu,
		//timing model interface
		input   tm2cpu_token_type         tm2cpu
		);	
		
	spr_parity_type		    spre, sprd;   //parity encode/decode
	spr_commit_type 	    spro;		       //read result for spr register
	bit [NTHREADIDMSB:0]	rthid, wthid;	//write thread id (power of 2)
	
	typedef struct {
		bit [NTHREADIDMSB:0]	tid;
		bit			               tid_parity;	
		spr_commit_type		    spr;
		spr_parity_type		    parity;
		microcode_out_type	  uco;
		//new scheduler signal
		bit                  nodma;		
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
			spre.archr   = ^{comr.spr.psr.pil, comr.spr.psr.ef, comr.spr.psr.icc, comr.spr.fsr, comr.spr.wim};
			spre.ts      = ^{comr.spr.icmiss, comr.spr.replay, comr.spr.annul, comr.spr.ucmode, comr.spr.upc, comr.spr.dma_mode};
			spre.psr     = ^{comr.spr.psr.s, comr.spr.psr.ps, comr.spr.psr.et, comr.spr.psr.cwp};
			spre.y       = '0;       //no use
			//decoding
			//parity_error = delr.parity.pc | delr.parity.npc | delr.parity.archr | delr.parity.ts | delr.parity.y;						
			parity_error = |delr.parity ;
		end
		else begin
		  spre = '{0, 0, 0, 0, 0, 0};
		  parity_error = '0;
		end

		//MMU/cache result relay stage
		derin.ts.tid        = delr.tid;
		derin.ts.tid_parity = delr.tid_parity;
		
		derin.ts.run        = delr.spr.run;
		derin.ts.valid      = delr.spr.valid;
		derin.ts.replay     = delr.spr.replay;
		derin.ts.icmiss     = delr.spr.icmiss;
		derin.ts.annul      = delr.spr.annul;
		derin.ts.ucmode     = delr.spr.ucmode;
		derin.ts.psr        = delr.spr.psr;
		derin.ts.fsr        = delr.spr.fsr;
		derin.ts.y          = delr.spr.y;
		derin.ts.wim        = delr.spr.wim;
		derin.ts.pc         = delr.spr.pc;
		derin.ts.npc        = delr.spr.npc;
		
		derin.ts.upc        = delr.spr.upc;
		derin.ts.uend       = delr.uco.uend;
		
		derin.ts.flushidx   = delr.spr.flushidx;
		
    //dma mode
		derin.ts.dma_mode   = delr.spr.dma_mode;
		derin.ts.dma_state  = dma2iu.state;
		
				
		//decode microcode indirection bits 
		derin.ts.rdmask = delr.spr.ucmode & delr.uco.inst[UCIPOS_RD]  & ~delr.uco.cwp_rd;
		derin.rs1mask   = delr.spr.ucmode & delr.uco.inst[UCIPOS_RS1] & ~delr.uco.cwp_rs1;
		derin.rs2mask   = delr.spr.ucmode & delr.uco.inst[UCIPOS_RS2] & ~delr.uco.inst[13];		
		derin.cwp_rs1   = delr.uco.cwp_rs1;
		derin.cwp_rd    = delr.uco.cwp_rd;
				
		//derin.ts.inst   = {icache_if_out[7:0], icache_if_out[15:8], icache_if_out[23:16], icache_if_out[31:24]};		//input from icache, big endian		
	  derin.ts.inst   = (delr.spr.dma_mode)? dma2iu.inst : ldst_big_endian(icache_if_out);
		derin.microinst = delr.uco.inst;	//microcode  
		
		//new scheduler will disable the dma_mode if the thread is not scheduled
		if (newsch & delr.nodma) begin   
      derin.ts.dma_mode  = '0;
      derin.ts.dma_state =  dma_NOP;
      
      derin.ts.inst = 32'h01000000;       //do nothing 
    end

		//does nothing (will be optimized away)
		derin.ts.ldst_a = '0;
		derin.ts.asi    = '0;
	end

  assign tid_parity = (LUTRAMPROT)? ^tm2cpu.tid : '0;

	always_ff @(posedge gclk.clk) begin		
		//relay registers for MMU/cache compare stage
		delr.tid        <= tm2cpu.tid;
		delr.tid_parity <= tid_parity;
		delr.spr        <= spro;
		delr.uco        <= uco;		//microcode output
		
		delr.nodma      <= (rst) ? '0 : tm2cpu.running & ~tm2cpu.run;

		if (LUTRAMPROT)	begin 
			//parity decoding 
			delr.parity.pc    <= ^spro.pc ^ sprd.pc;
			delr.parity.npc   <= ^spro.npc ^ sprd.npc;
			delr.parity.archr <= ^{spro.psr, spro.fsr, spro.wim} ^ sprd.archr;
			delr.parity.ts    <= ^{spro.flushidx, spro.icmiss, spro.replay, spro.annul, spro.ucmode, spro.upc, spro.dma_mode} ^ sprd.ts;
			delr.parity.y     <= ^spro.y.y ^ sprd.y;           //can be written as ^spro.y
			delr.parity.psr   <= ^spro.psr;
		end
		else begin
			delr.parity    <= '{0, 0, 0, 0, 0, 0};
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
  assign mmucache_valid = spro.run & ~spro.dma_mode & ~(spro.ucmode && spro.upc < UPC_ST);         //don't need rst here? immu won't do an;ythin global reset

	//I-MMU input signals		
	assign immu_if_in.tid          = tm2cpu.tid;
	assign immu_if_in.vpc          = spro.pc;
	assign immu_if_in.valid        = mmucache_valid;
	assign immu_if_in.su           = spro.psr.s;
	assign immu_if_in.replay       = spro.replay;
	assign immu_if_in.vpc_parity   = sprd.pc;
  //second cycle IF input
  assign immu_if_in.iflush     = is_flush(derin.ts);
  assign immu_if_in.flushidx   = derin.ts.flushidx;


	//I$ read request
	assign icache_if_in.tid        = tm2cpu.tid;
	assign	icache_if_in.tid_parity = tid_parity;
	assign	icache_if_in.vpc        = spro.pc;
	assign	icache_if_in.valid      = mmucache_valid;
	assign	icache_if_in.replay     = spro.replay;

  //dma output
  assign dma_rtid = tm2cpu.tid;
  			
	//microcode rom
	microcode_rom ucode(.upc(spro.upc), .uco); 	
endmodule