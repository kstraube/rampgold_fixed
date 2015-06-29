//-------------------------------------------------------------------------------------------  
// File:        exception_dma.sv
// Author:      Zhangxi Tan
// Description: Functions and modules used in exception stage with dma support
//		Future software 32-bit ECC and debugging will add internal pipeline stages
//-------------------------------------------------------------------------------------------   
`timescale 1ns / 1ps
`ifndef SYNP94
import libconf::*;
import libiu::*;
import libopcodes::*;
import libucode::*;
import libmmu::*;
import libcache::*;
import libdebug::*;
import libtm::*;
import libperfcnt::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`include "../tm/libtm.sv"
`endif

//Synplify/Precision, please work hard on this file. These functions are huge!
//probably add another writeback stage

//ld align stays here, because signals from BRAM read port might take 1 extra cycle to route
function automatic bit [31:0] ld_align(bit [31:0] data, bit [3:0] byte_mask, bit signext);
`ifndef SYNP94
	bit [31:0] aligned_data = data;
`else
	bit [31:0] aligned_data;
	aligned_data = data;
`endif
//sv conditional operator problems?
/*
	unique case(byte_mask)
	4'b0001: aligned_data = (signext)? signed'(data[31:24]) : unsigned'(data[31:24]);
	4'b0010: aligned_data = (signext)? signed'(data[23:16]) : unsigned'(data[23:16]); 
	4'b0100: aligned_data = (signext)? signed'(data[15:8])  : unsigned'(data[15:8]);
	4'b1000: aligned_data = (signext)? signed'(data[7:0])   : unsigned'(data[7:0]);
	4'b0011: aligned_data = (signext)? signed'({data[23:16],data[31:24]}) : unsigned'({data[23:16],data[31:24]});
	4'b1100: aligned_data = (signext)? signed'({data[7:0],data[15:8]})    : unsigned'({data[7:0],data[15:8]});
	default: aligned_data = data;
	endcase
*/

	unique case(byte_mask)
	4'b0001: if (signext) aligned_data = signed'(data[31:24]); else aligned_data = unsigned'(data[31:24]);
	4'b0010: if (signext) aligned_data = signed'(data[23:16]); else aligned_data = unsigned'(data[23:16]); 
  4'b0100: if (signext) aligned_data = signed'(data[15:8]);  else aligned_data = unsigned'(data[15:8]);
	4'b1000: if (signext) aligned_data = signed'(data[7:0]);   else aligned_data = unsigned'(data[7:0]);
	4'b0011: if (signext) aligned_data = signed'({data[31:24],data[23:16]}); else aligned_data = unsigned'({data[31:24],data[23:16]});
	4'b1100: if (signext) aligned_data = signed'({data[15:8],data[7:0]});    else aligned_data = unsigned'({data[15:8],data[7:0]});
	default: aligned_data = data;
	endcase

	return aligned_data;
endfunction

//currently doesn't support advanced features such as branch, automatic register window handling in microcode. They will be supported in future.
task automatic decode_microcode_mode(input xc_reg_type r, input bit trap, output bit [NUPCMSB:0] upc, output bit ucmode);
`ifndef SYNP94
	bit [1:0]       op      = r.ts.inst[31:30];
	bit [5:0]       op3     = r.ts.inst[24:19];
	logic [NUPCMSB:0] micropc = 'x;	 //microcode pc
	bit	            uc      = '0;		//microcode mode
`else
	bit [1:0]       op;
	bit [5:0]       op3;
	logic [NUPCMSB:0] micropc;	 //microcode pc
	bit	            uc;			 //microcode mode
	
	op      = r.ts.inst[31:30];
	op3     = r.ts.inst[24:19];
	micropc = 'x;	 //microcode pc
	uc      = '0;		//microcode mode
`endif	

	if (trap == 1'b1) begin		//trap
		micropc = UPC_TRAP;		//store pc->r[17], tt->temp
		uc = '1;
	end
	else begin
		unique case(op)
		  FMT3: begin 		
  		          unique case(op3) 
                WRTBR: begin micropc = UPC_WRTBR; uc = '1; end          
  		            FLUSH: begin micropc = UPC_FLUSH; uc = '1; end
		          default: ;
		          endcase
		        end		          
		  LDST: unique case(op3)	//only support LDST now
			ST, STA, STC, STFSR, STCSR : begin micropc = UPC_ST; uc = '1; end
			STB, STBA: begin micropc = UPC_STB; uc = '1;end
			STH, STHA: begin micropc = UPC_STH; uc = '1;end
			STDFQ, STDCQ, STD, STDA, STDF, STDC: begin micropc = UPC_STD; uc = '1; end
			SWAP, SWAPA: begin micropc = UPC_SWAP; uc ='1; end 				
			LDSTUB, LDSTUBA: begin micropc = UPC_LDST; uc ='1; end		
			default: ;	//does nothing
			endcase
		default: ;	//does nothing
		endcase
	end
	
	upc = micropc;
	ucmode = uc;
endtask

//modify cwp for trap
function automatic bit [NWINMSB:0] new_cwp_trap(xc_reg_type r, bit trap);
`ifndef SYNP94
	bit [NWINMSB:0]          retcwp = r.ts.psr.cwp;
`else
	bit [NWINMSB:0]          retcwp;
	retcwp = r.ts.psr.cwp;
`endif	

	if (trap == 1'b1) 
      retcwp = (r.ts.psr.cwp == CWPMIN)? CWPMAX : r.ts.psr.cwp - 1;
 	
	return retcwp;
endfunction

task automatic rd_gen(input xc_reg_type          r, 
            input bit [31:0]           paddr,		     //physical address for store
            input bit                  trap,			     //trap
            input bit                  replay,      //replay 
            input bit                  error_mode,  //error_mode
        	   input bit [NWINMSB:0]      cwp,		       //cwp in PSR 
	          output bit [NREGADDRMSB:0] rdaddr1, rdaddr2, 
        	   output bit [31:0]          rdata1, rdata2, 
        	   output bit                 we1, we2,
        	   output bit [31:0]          debug_dma_data);
	bit [NREGADDRMSB:0] rda1, rda2; 
	
	bit  ignrd;    //disable rd = 0 check for CALL and WRTBR
	
	bit [31:0] dma_data;

`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [2:0] op2 = r.ts.inst[24:22];
	bit [5:0] op3 = r.ts.inst[24:19];
	bit [4:0] rs1 = r.ts.inst[18:14];

	bit wreg1 = '0; 
	bit wreg2 = '0;

	bit [4:0] rd1 = r.ts.inst[29:25];
	bit [4:0] rd2 = r.ts.inst[29:25];

	bit [31:0] da1 = r.ex_res, da2 = ld_align((r.io_op)? r.io_res[31:0] : r.mem_res[31:0], r.byte_mask, r.signext);	//by default, da1 = alu ouput, da2 = ld data
	
	bit spr1 = '0;		//indicates rd1 in scratch pad 
	bit spr2 = '0;  //indicates rd2 in scratch pad
`else
	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;
	bit [4:0] rs1;

	bit wreg1; 
	bit wreg2;

	bit [4:0] rd1;
	bit [4:0] rd2;

	bit [31:0] da1, da2;	//by default, da1 = alu ouput, da2 = ld data
	
	bit spr1;		//indicates rd1 in scratch pad 
	bit spr2;  		//indicates rd2 in scratch pad

	op  = r.ts.inst[31:30];
	op2 = r.ts.inst[24:22];
	op3 = r.ts.inst[24:19];
	rs1 = r.ts.inst[18:14];

	wreg1 = '0; 
	wreg2 = '0;

	rd1 = r.ts.inst[29:25];
	rd2 = r.ts.inst[29:25];

	da1 = r.ex_res; da2 = ld_align((r.io_op)? r.io_res[31:0] : r.mem_res[31:0], r.byte_mask, r.signext);	//by default, da1 = alu ouput, da2 = ld data
	
	spr1 = '0;		//indicates rd1 in scratch pad 
	spr2 = '0;  //indicates rd2 in scratch pad
`endif
	
	ignrd    = '0;
	dma_data = da2;
		
	unique case (op)
	CALL: begin 
		      wreg1 = '1; rd1 = 5'd15;		//CALL saves PC in r[15] (%o7)
        		da1 = {r.ts.pc, 2'b0};
        		ignrd = '1;
	      end
	FMT2: begin 
	       if (op2 == SETHI) wreg1 = '1;	 
	      end
	FMT3: begin 
	  if (ADVDEBUGDMA)
	     dma_data = da1;
  	  unique case(op3)
		  WRY : if (rs1 >= 8 && ASREN == 1) begin		           //handle WRASR, can't clobber g0 - g7
          			rd1 = {1'b0, rs1}; spr1 = '1;
          			wreg1 = '1;
		        end
  //		WRTBR : begin rd1 = REGADDR_TBR; wreg1 = '1; spr1 = '1;  end
      WRTBR : begin rd1 = REGADDR_SCRATCH_0; da1[11:0] = '0; wreg1 = '1; spr1 = '1; ignrd = '1; end
    		JMPL  : begin da1 = {r.ts.pc, 2'b0}; wreg1 = '1; end	//pc -> rd 			
      TICC  : wreg1 = '0;
		  FLUSH : begin 	
		            wreg1 = ~r.ts.ucmode; ignrd = '1;
		            da1 = paddr; rd1 = REGADDR_SCRATCH_0; spr1 = '1;
              end
    		default: wreg1 = '1;
    		endcase
	  end
	LDST: begin
		unique case(op3)
		ST, STA, STB, STBA, STH, STHA, STD, STDA: begin 
		                                                //wreg1 = '1;   //no harm in microcode mode if use REG_SCRATCH_0 as address
		                                                wreg1 = ~r.ts.ucmode;
		                                                ignrd = '1;
		                                                da1 = paddr; rd1 = REGADDR_SCRATCH_0; spr1 = '1;
                                            		end	                              		
		LD, LDA, LDUB, LDUBA, LDUH, LDUHA, LDD, LDDA, LDSB, LDSBA, LDSH, LDSHA: begin
			wreg2 = '1; 	
			if (op3 == LDD || op3 == LDDA) begin	
			   wreg1 = '1; rd1[0] = '1; da1 = r.mem_res[63:32]; 
			   ignrd = '1;   //destination can't be g0
			 end		
			end
		LDSTUB, LDSTUBA, SWAP, SWAPA: begin 
				wreg1 = '1; wreg2 = '1; spr1 = '1; ignrd = '1;
				rd1 = REGADDR_SCRATCH_0; da1 = paddr;
				if (op3 == SWAP || op3 == SWAPA) begin
          spr2 = '1;
					rd2 = REGADDR_SCRATCH_1;	//can't clobber rd in swap, but don't need ignrd here
				end
			end
		default: ;
		endcase
		end
	endcase	

	if (trap == 1'b1) begin
		wreg1 = '1;  

    wreg2 = (error_mode == 1 && V8_ERROR_MODE>0) ? '0 : '1;
	  rd1   = (error_mode == 1 && V8_ERROR_MODE>0) ? REGADDR_TBR : REGADDR_SCRATCH_0;	//write tt -> scratch / tbr (error mode only)
    
		da1 = {20'b0, r.trap_res.tbr_tt, 4'b0}; 
		spr1 = '1;  
		
		rd2 = 5'd18;		//write npc -> r[18]
		da2 = {r.ts.npc, 2'b0};
	end
		
	if (spr1 == 1'b1 || r.ts.rdmask == 1'b1)		//in special register
		rda1 = {r.ts.tid, 3'b001, rd1[2:0]};
	else
		rda1 = regaddr(r.ts.tid, cwp, rd1);
	rdaddr1 = rda1;

	if (spr2 == 1'b1 || r.ts.rdmask == 1'b1)
		rda2 = {r.ts.tid, 3'b001, rd2[2:0]};
	else
		rda2 = regaddr(r.ts.tid, cwp, rd2);
	rdaddr2 = rda2;

	//we1 = wreg1 & ((|r.ts.inst[29:25]) | op == CALL) & r.ts.run & !r.invalid & (!r.ts.annul_trap | r.ts.ucmode) & !r.ts.replay;  //CALL only writes to 1 register
 	//we2 = wreg2 & (|r.ts.inst[29:25]) & r.ts.run & !r.invalid & (!r.ts.annul_trap | r.ts.ucmode) & !r.ts.replay;
  we1 = wreg1 & ((|r.ts.inst[29:25]) | ignrd | trap) & (r.ts.run | r.ts.dma_mode) & (~r.invalid | trap )& ~r.ts.annul & ~replay;  //CALL only writes to 1 register
  we2 = wreg2 & (|r.ts.inst[29:25] | trap) & (r.ts.run | r.ts.dma_mode) & (~r.invalid | trap) & ~r.ts.annul & ~replay;
 
	rdata1 = da1; rdata2 = da2; 	
	debug_dma_data = dma_data;
endtask

//special write control for rd and npc
//wnpc: update npc from ALU: BICC, CALL, JMPL, RETT
//rett:	RETT 
task automatic sp_write(input xc_reg_type r, output bit npc, rett, psr, wim, y, pc);
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [2:0] op2 = r.ts.inst[24:22];
	bit [5:0] op3 = r.ts.inst[24:19];
	
	bit wnpc = '0, ret_t = '0, wrwim = '0, wrpsr = '0, wry = '0, wpc = '0;
`else
	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;
	
	bit wnpc, ret_t, wrwim, wrpsr, wry, wpc;
	
	op  = r.ts.inst[31:30];
	op2 = r.ts.inst[24:22];
	op3 = r.ts.inst[24:19];
	
	wnpc = '0; ret_t = '0; wrwim = '0; wrpsr = '0; wry = '0; wpc = '0;
`endif

	unique case (op)
	CALL: wnpc = '1;
	FMT2: unique case(op2)
	      BICC, FBFCC, CBCCC: wnpc = r.branch_true;
	      default: ;
	      endcase
	FMT3: unique case(op3)
	      JMPL:  begin wnpc  = '1;
                     if (r.ts.dma_mode) begin
                       wnpc = ~r.ts.inst[13];   //i=0, wnpc
                       wpc  = r.ts.inst[13];    //i=1, wpc
                     end
	             end
	      RETT:  begin wnpc = '1; ret_t = '1; end
	      WRPSR: wrpsr = '1;
	      WRWIM: wrwim = '1;
	      WRY  : wry   = '1;
	      default: ;
	      endcase
	default:;
	endcase
	
	npc = wnpc; rett = ret_t;  psr = wrpsr; wim = wrwim; y = wry; pc = wpc;
	
endtask

module exception_stage_dma(input iu_clk_type gclk, input bit rst, 
		       input 	xc_reg_type 		      xcr,
		       input 	dmmu_iu_out_type 	  dmmu2iu,
		       input 	cache2iu_ctrl_type 	dcache2iu, 
		       output	commit_reg_type 	   comr,
		       output	bit			              luterr,
		       output	bit			              bramerr,
		       output	bit			              sb_ecc,
		       // performance counter interface
		       output perf_count_write_req_in cpu2pc,
		       //debug dma interface
		       output debug_dma_in_type         iu2dma,
		       //pipeline start/stop control (timing model interface)
           output tm_cpu_ctrl_token_type    cpu2tm
		       );
	bit trap_detected; 
	bit ucmode;		//microcode mode
	bit replay;	 //replay bit

  //debug dma related signals
	bit        cpu_stoppable;
	bit        dma_done;
	bit [31:0] dma_data;

	//pipeline register
	//commit_reg_type	cr, crin;
  commit_reg_type crin;

	bit		wnpc, rett, wrwim, wrpsr, wy;	       //special write flags;
	bit  wpc;                                 //used by debugging
	
	bit  error_mode;
	bit [7:0]	tbr_tt;				//tt field for TBR
  
  //timing model output register
  tm_cpu_ctrl_token_type  v_cpu2tm;

  assign cpu2pc.inst = xcr.ts.inst;
  assign cpu2pc.tid = xcr.ts.tid;
  assign cpu2pc.valid = ~replay & xcr.ts.run & ~xcr.ts.ucmode;
   
	assign	luterr  = dcache2iu.luterr;
	assign	bramerr = dcache2iu.bramerr;
	assign	sb_ecc  = dcache2iu.sb_ecc; 
	
  always_comb begin
		sp_write(xcr, wnpc, rett, wrpsr, wrwim, wy, wpc);

		//default values
		error_mode = '0;
		replay     = xcr.ts.replay | dcache2iu.replay;

		crin.spr.replay   = replay;	              //replay bit
		crin.spr.icmiss   = xcr.ts.icmiss;        //icache miss
		crin.spr.run      = xcr.ts.run;
		
		crin.spr.flushidx = xcr.ex_res[ICACHEINDEXMSB_IU:ICACHEINDEXLSB_IU];
		
		crin.spr.psr = xcr.ts.psr;
		crin.spr.y   = xcr.ts.y;
		crin.spr.wim = xcr.ts.wim;
		
		//detect trap: advance cwp and etc
		//trap_detected = (xcr.trap_res.precise_trap | dmmu2iu.exception | xcr.trap_res.irq_trap) & ~replay & ~xcr.ts.ucmode;
		trap_detected = (xcr.trap_res.precise_trap | dmmu2iu.exception | xcr.trap_res.irq_trap) & ~replay & ~xcr.ts.dma_mode;    //assume microcode is well written?
		crin.spr.psr.cwp = new_cwp_trap(xcr, trap_detected);
		
		//error mode if detect precise trap when ET=0,
    if (xcr.ts.run == 1'b1 && xcr.ts.dma_mode == 0 && xcr.ts.ucmode == 1'b0 && xcr.ts.annul == 1'b0 && replay == 0) 
      error_mode = (xcr.trap_res.precise_trap == 1'b1 && xcr.ts.psr.et == 1'b0)? '1 : '0;

		
		//overide trap type based on priority
		if (!xcr.trap_res.nodaex && dmmu2iu.exception)
			tbr_tt = TT_DAEX;
		else
			tbr_tt = xcr.trap_res.tbr_tt;

		//decode microcode mode	
		decode_microcode_mode(xcr, trap_detected, crin.spr.upc, ucmode);
		
		//modify ucmode and upc, if no replay
		if (!replay) begin
			//crin.spr.ucmode = (xcr.ts.ucmode == 1'b1)? !xcr.ts.uend : !xcr.invalid & !xcr.ts.annul & ucmode;
			crin.spr.ucmode = (xcr.ts.ucmode == 1'b1)? ~xcr.ts.uend : ~xcr.ts.annul & ucmode;
			if (xcr.ts.ucmode)
				crin.spr.upc = xcr.ts.upc + 1;
		end
		else begin
			crin.spr.ucmode = xcr.ts.ucmode;
			crin.spr.upc    = xcr.ts.upc;
		end
		//crin.spr.ucmode = (xcr.ts.ucmode == 1'b1)? !xcr.ts.uend : !xcr.ts.annul & ucmode;
		
		
		//annul_next (integer only now) or trap indicator
    if (xcr.ts.icmiss | xcr.ts.dma_mode | xcr.ts.run == 1'b0)
      crin.spr.annul = xcr.ts.annul;  //no change
    else
      crin.spr.annul = ~xcr.invalid & ~xcr.ts.annul & xcr.annul_next & ~trap_detected;		

		
		if (trap_detected == 1'b1) begin
			crin.spr.psr.et = '0;
			crin.spr.psr.ps = xcr.ts.psr.s;
			crin.spr.psr.s = '1;
		end
		else if (rett == 1'b1) begin
			crin.spr.psr.et = '1;
			crin.spr.psr.s = xcr.ts.psr.ps;
		end
			
		//wrpsr, wrwim, wry
		if (wrpsr == 1'b1 && !trap_detected) begin
			crin.spr.psr.icc = xcr.ex_res[23:20];
			crin.spr.psr.pil = xcr.ex_res[11:8];
			crin.spr.psr.s   = xcr.ex_res[7];
			crin.spr.psr.ps  = xcr.ex_res[6];
			crin.spr.psr.et  = xcr.ex_res[5];
			crin.spr.psr.cwp = xcr.ex_res[NWINMSB:0];
		end
				
		if (wrwim == 1'b1 && !trap_detected)
			crin.spr.wim = xcr.ex_res[NWIN-1:0];	
			
		if (wy) begin
	    crin.spr.y.y      = xcr.ex_res;
	    crin.spr.y.parity = (LUTRAMPROT) ? ^xcr.ex_res : '0;
	  end
									
		//currently, doesn't suppport wrpsr, wrwim in microcode mode
		//use xcr.ts.run instead of crin.spr.run, just let psr, wim garbled in error mode
		//crin.spr.archr_we = xcr.ts.run & !xcr.invalid & !xcr.ts.ucmode & !xcr.ts.annul_trap & !replay;		
		crin.spr.archr_we = xcr.ts.run & ~xcr.ts.ucmode & ~xcr.ts.annul & ~replay & ~xcr.ts.dma_mode;		
		crin.spr.archr_we |= xcr.ts.dma_mode & (wrpsr | wrwim | wy);

		crin.spr.run = crin.spr.run & ~dcache2iu.luterr & ~dcache2iu.bramerr;
		
		//With DMA and timing models, always restart the CPU when pipeline enters the error mode
		//if (V8_ERROR_MODE == 0 && error_mode == 1)
		//  crin.spr.run = '0;        //stop if no error mode implementation
		
		rd_gen(xcr, dmmu2iu.paddr, trap_detected, replay, error_mode, crin.spr.psr.cwp, crin.regf.ph1_addr, crin.regf.ph2_addr, crin.regf.ph1_data, crin.regf.ph2_data, crin.regf.ph1_we, crin.regf.ph2_we, dma_data);

		crin.regf.ph1_parity = '0; crin.regf.ph2_parity = '0;
		if (BRAMPROT == 1) begin	//parity bit encoding
			crin.regf.ph1_parity[6] = ^crin.regf.ph1_data;
			crin.regf.ph2_parity[6] = ^crin.regf.ph2_data;
		end
		
		//generate pc, npc;						
		//if (wnpc == 1'b1 && ((xcr.ts.annul_trap == 1'b0 && xcr.ts.ucmode == 1'b0) || xcr.ts.ucmode))	//wnpc = 1 => invalid = 0
		if (wnpc == 1'b1 && (((xcr.ts.annul == 1'b0 || xcr.ts.dma_mode == 1'b0) && xcr.ts.ucmode == 1'b0) || xcr.ts.ucmode))	//wnpc = 1 => invalid = 0
			crin.spr.npc = xcr.ex_res[31:2];
		else
			crin.spr.npc = 	xcr.ts.npc + 1;	//by default npc + 4, use DSP if we have extra to burn			

    crin.spr.pc = (wpc)? xcr.ex_res[31:2] : xcr.ts.npc;		//pc <- npc;

		//npc can be modified using jump, call, bicc in microcode
    if (wnpc)
    		crin.spr.npc_we = (xcr.ts.run & ~replay) | xcr.ts.dma_mode;	//annul and invalid(fop) are nops for integer pipe
		else if (crin.spr.ucmode)                 //just enter microcode mode
		  crin.spr.npc_we = '0;
		else                                      //default case
		  crin.spr.npc_we = xcr.ts.run & ~replay & ~xcr.ts.dma_mode;	
		 		   
		crin.spr.pc_we = xcr.ts.run & (~crin.spr.ucmode | (xcr.ts.uend & xcr.ts.ucmode)) & ~replay & ~xcr.ts.dma_mode;			//pc is not touched in ucmode		
		crin.spr.pc_we    |= xcr.ts.dma_mode & wpc;
		
				
		crin.spr.ts_we = xcr.ts.run | xcr.ts.dma_mode | (xcr.ts.dma_state.cmd == dma_OP);
		
		//debugging dma related signals
    cpu_stoppable = (~crin.spr.ucmode | (xcr.ts.uend & xcr.ts.ucmode)) & ~replay & ~trap_detected;

    dma_done = '0;
    
    crin.spr.dma_mode = xcr.ts.dma_mode;          //default
    if (cpu_stoppable) begin 
        if (xcr.ts.dma_state.cmd == dma_OP) begin
    			       if (xcr.ts.dma_state.count == 0) begin		//the last one from dma
         				      crin.spr.dma_mode = ~xcr.ts.dma_mode;
         				      dma_done = xcr.ts.dma_mode;
      			     end
     			      else 
                   crin.spr.dma_mode = '1;				        	     
		    end
 	  end
 	  

    iu2dma.tid        = xcr.ts.tid;
    iu2dma.done       = dma_done;
	  iu2dma.ack        = cpu_stoppable & xcr.ts.dma_mode;     //only used for dma write buffer we, may or may not toggled for dma_start_cpu/dma_stop_cpu
    iu2dma.state      = xcr.ts.dma_state;
    iu2dma.state.data = dma_data;       //update the data field for LD, FMT3 result


	  v_cpu2tm.tid   = xcr.ts.tid;
	  v_cpu2tm.valid = cpu_stoppable & ~xcr.ts.dma_mode;
  end

  function automatic commit_reg_type get_comr();
`ifndef SYNP94
    commit_reg_type cr = crin;
`else
    commit_reg_type cr;
    cr = crin;
`endif    

    cr.spr.run = '0;      //no use in DMA mode, should be optimized away
    
    if (rst == 1'b1) begin
      cr.spr.pc_we    = (SPRBRAM == 1'b0)? '1 : '0;		//WE for pc
      cr.spr.npc_we   = (SPRBRAM == 1'b0)? '1 : '0;		//WE for npc
      cr.spr.archr_we = (SPRBRAM == 1'b0)? '1 : '0;		//WE for architecture registers
      cr.spr.ts_we    = (SPRBRAM == 1'b0)? '1 : '0;		//WE for everything else
      //preset value at reset
      cr.spr.pc  = '0;	cr.spr.npc = 1;			
      cr.spr.psr = init_psr;
      cr.spr.y   = init_y;
      

      //start a thread when thread_mask indicates it's runnable			
      cr.spr.ucmode = '0; cr.spr.replay = '0; cr.spr.annul = '0;
      cr.spr.icmiss = '0; //cr.spr.wim = '0;
      
      /*
      cr.regf.ph1_we = '0;
      cr.regf.ph2_we = '0; */
      
      cr.regf.ph2_addr[NREGADDRMSB-NTHREADIDMSB-1:0] = '0;      
      cr.regf.ph2_we     = '1;
      cr.regf.ph2_data   = '0;          //write 0 to reg 0.
      cr.regf.ph2_parity = '0;
    
      if (ASR15EN) begin
        cr.regf.ph1_we = '1;
        cr.regf.ph1_addr = {xcr.ts.tid, 6'd15};
        cr.regf.ph1_data = unsigned'(xcr.ts.tid);
      end
      else
        cr.regf.ph1_we = '0;      
    end	
    else if (error_mode && V8_ERROR_MODE>0) begin
      //synthesis translate_off
        if (xcr.ts.run)
         $display("@%t: Thread %d enters error mode", $time, xcr.ts.tid);
      //synthesis translate_on   
      
      cr.spr.pc_we    = (SPRBRAM == 1'b0)? '1 : '0;		//WE for pc
      cr.spr.npc_we   = (SPRBRAM == 1'b0)? '1 : '0;		//WE for npc
      cr.spr.archr_we = (SPRBRAM == 1'b0)? '1 : '0;		//WE for architecture registers
      //preset value at reset
      cr.spr.pc  = '0;	cr.spr.npc = 1;			
      
      //cr.spr.psr.et = '0;
      //cr.spr.psr.s = '1; cr.spr.psr.cwp = xcr.ts.psr.cwp;
      cr.spr.psr = init_psr;  cr.spr.wim = '0;
      
      cr.spr.ucmode = '0; cr.spr.replay = '0; cr.spr.annul = '0;
      cr.spr.icmiss = '0;
    end
  
    return cr;
  endfunction
  
  //pipeline register
  always_ff @(posedge gclk.clk) begin
    comr   <= get_comr();
    
    cpu2tm <= v_cpu2tm;
  end
  
endmodule
