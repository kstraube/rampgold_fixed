//------------------------------------------------------------------------------ 
// File:        memory.v
// Author:      Zhangxi Tan
// Description: Functions and modules used in memory stage
//------------------------------------------------------------------------------  
`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libopcodes::*;
import libucode::*;
import libcache::*;
import libmmu::*;
import libio::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`include "../io/libio.sv"
`endif

//Final trap detection. imprecise IRQ trap is detected here
//put IRQ here to see how Synplify works
typedef struct {	
	bit		     psr_trap;	  //psr illegal cwp
	bit		     align_trap;	//unaligned address
//	bit		daex_trap;	//data access (mmu invalid addr trap)
	bit		     tag_trap;	  //tag 
	bit		     divz_trap;	 //divide by zero 
	bit		     ticc_trap;	 //ticc trap	
	bit       ieee754_trap; // fpu execution trap
	trap_type	tt;		       //other encoded trap type, e.g. window overflow
	bit		     trap;		     //other traps are detected
//imprecise trap (IRQ)
	bit [3:0] irl;		      //IRQ
}detected_trap_type;			 //detected precise trap

//---------------------------------------------------1st cycle functions--------------------------------------
//decode ld/st 
function automatic LDST_CTRL_TYPE decode_ldst(bit[31:0] inst, bit ucmode);
	bit	[1:0] ret;			//this is to fix a known precision issue	
`ifndef SYNP94
	bit load = '0, store = '0;
	bit [1:0] op  = inst[31:30];
	bit [5:0] op3 = inst[24:19];		
`else
	bit load, store;
	bit [1:0] op;
	bit [5:0] op3;		

	load = '0; store = '0;
	op  = inst[31:30];
	op3 = inst[24:19];		
`endif	
	
	if (!ucmode) 		
		load = (op == LDST) ? '1 : '0;
	else begin
		if (op == LDST && (op3[2] == 1'b0 || op3[3] == 1'b1))
			load = '1;

		if (op == LDST && op3[3:2] == 2'b01)
			store =  '1;
	end
	
	if (op == FMT3 && op3 == FLUSH) begin
	    load  = '1;
    	store = '1;
  end
	
	ret = {load, store};
	return LDST_CTRL_TYPE'(ret);
	
endfunction

//1st cycle trap detection
//detect address unalign exception
function automatic bit detect_unalign_exception(bit [31:0] inst, bit [31:0] addr);
`ifndef SYNP94
	bit [1:0] op  = inst[31:30];
	bit [5:0] op3 = inst[24:19];	

	bit unalign = '0;
`else
	bit [1:0] op;
	bit [5:0] op3;	

	bit unalign;

	op  = inst[31:30];
	op3 = inst[24:19];	

	unalign = '0;
`endif

	unique case(op)
	FMT3:	if (op3 == JMPL || op3 == RETT)
			unalign = |(addr[1:0]);
	LDST:	unique case(op3)
		LD, LDA, ST, STA, SWAP, SWAPA, LDF, LDC, LDFSR, LDCSR, STF, STC, STFSR, STCSR: 										unalign = |(addr[1:0]);
 		LDD, LDDA, STD, STDA, LDDF, LDDC, STDF, STDC, STDFQ, STDCQ: unalign = |(addr[2:0]);
		LDUH, LDUHA, STH, STHA, LDSH, LDSHA : unalign = addr[0];
		default:;
		endcase
	default: ;
	endcase

	return unalign;
endfunction

//detect PSR exceptions (privilege instructions), generated by WRPSR instruction only
function automatic bit detect_psr_exception(bit [31:0] inst, bit [31:0] alu_result);
`ifndef SYNP94
	bit [1:0] op  = inst[31:30];
	bit [5:0] op3 = inst[24:19];	
	
	bit psr_ex = '0;
`else
	bit [1:0] op;
	bit [5:0] op3;	

	bit psr_ex;

	op  = inst[31:30];
	op3 = inst[24:19];	
	
	psr_ex = '0;
`endif	
	
	if (op == FMT3 && op3 == WRPSR && alu_result[4:0] > CWPMAX)
			psr_ex = '1;

	return psr_ex;
endfunction

//---------------------------------------------------2nd cycle functions--------------------------------------
//prepare store data
function automatic bit [31:0] store_alignment(bit [31:0] inst, bit [31:0] addr, bit [31:0] stdata);
`ifndef SYNP94
  bit [1:0] op  = inst[31:30];
  bit [5:0] op3 = inst[24:19];	

  bit [31:0] data = stdata;
`else
  bit [1:0] op;
  bit [5:0] op3;	

  bit [31:0] data;

  op  = inst[31:30];
  op3 = inst[24:19];	

  data = stdata;
`endif
  
  if (op == LDST) begin
    unique case(op3)
    STB, STBA: unique case(addr[1:0])
         2'b00: data[31:24] = stdata[7:0];
         2'b01: data[23:16] = stdata[7:0];
         2'b10: data[15:8]  = stdata[7:0];
         2'b11: data[7:0]   = stdata[7:0];
         default: ;
         endcase
    STH, STHA: if (addr[1] == 1'b0) data[31:16] = stdata[15:0];
    default:;
    endcase
  end

  return data;
endfunction

//decode ldst mask
task automatic decode_ldst_mask(input bit [31:0] inst, input bit [31:0] addr, output bit [3:0] byte_mask, output bit signed_extend);
`ifndef SYNP94
  bit [1:0] op  = inst[31:30];
  bit [5:0] op3 = inst[24:19];	

  bit [3:0] mask    = '0;
  bit       signext = '0;
`else
  bit [1:0] op;
  bit [5:0] op3;	

  bit [3:0] mask;
  bit       signext;
  
  op  = inst[31:30];
  op3 = inst[24:19];	

  mask    = '0;
  signext = '0;  
`endif
  
  if (op == LDST) begin
    unique case(op3)	
    LD, LDA, LDD, LDDA, ST, STA, STD, STDA, STF, STDF, STFSR: mask = '1;
    LDUB, LDUBA, LDSTUB, LDSTUBA, STB, STBA: mask[addr[1:0]] = 1'b1;
    LDUH, LDUHA, STH, STHA : mask = (addr[1] == 1'b1)? 4'b1100 :4'b0011;
    LDSB, LDSBA : begin mask[addr[1:0]] = 1'b1; signext = '1; end	     
    LDSH, LDSHA : begin mask = (addr[1] == 1'b1)? 4'b1100 :4'b0011; signext = '1; end	     
    default: ; //all FP, CP LDST instructions are LD/ST or LDD/STD, covered by default ?
    endcase	        
  end

  byte_mask = mask; signed_extend = signext;
endtask

function automatic bit is_atomic(thread_state_type ts);
  bit ret;

`ifndef SYNP94	
	bit [1:0] op  = ts.inst[31:30];
	bit [5:0] op3 = ts.inst[24:19];
`else
	bit [1:0] op;
	bit [5:0] op3;

	op  = ts.inst[31:30];
	op3 = ts.inst[24:19];
`endif

  ret = '0;

  if (ts.ucmode == 0) begin     //non microcode mode
    if (op == LDST) begin
     unique case (op3) 
     ST, STA, STD, STDA, STF, STDF, STFSR, STB,STBA, STH, STHA,
     LDSTUB, LDSTUBA, SWAP, SWAPA : ret = '1;
     default : ret = '0;
     endcase
    end
    else if (op == FMT3 && op3 == FLUSH)
  		ret = '1;
  end  // end ts.ucmode == 0
  else  begin //microcode mode
    unique case (ts.upc) 
    UPC_STD, UPC_LDST, UPC_STDF: ret = '1;
    default : ret = '0;
    endcase
  end
  
  return ret;
endfunction

function automatic bit no_ldreplay(thread_state_type ts);
  bit ret;

`ifndef SYNP94	
	bit [1:0] op  = ts.inst[31:30];
	bit [5:0] op3 = ts.inst[24:19];
`else
	bit [1:0] op;
	bit [5:0] op3;

	op  = ts.inst[31:30];
	op3 = ts.inst[24:19];
`endif

  ret = '0;

  if (ts.ucmode == 0) begin     //non microcode mode
    if (op == LDST) begin
     unique case (op3) 
     ST, STA, STD, STDA, STF, STDF, STFSR, STB,STBA, STH, STHA : ret = '1;
     default : ret = '0;
     endcase
    end
  end  
  return ret;
endfunction


//pre exception detection, used in the 2nd cycle of LDST
function automatic pre_trap_type pre_exception(thread_state_type ts, detected_trap_type t, bit [31:0] alu_res);
	pre_trap_type trap_res;	
`ifndef SYNP94
	bit ptrap = t.trap;
	bit irq_trap = '0;
	bit nodaex = '0;

	bit [7:0] tto = {1'b0,t.tt};
`else
	bit ptrap;
	bit irq_trap;
	bit nodaex;

	bit [7:0] tto;

	ptrap = t.trap;
	irq_trap = '0;
	nodaex = '0;

	tto = {1'b0,t.tt};
`endif	
	
	if (t.trap == 0) begin	
	//interrupt priority, no need to worry about TICC, it won't generate other exceptions
		ptrap = '1;		
		if (t.psr_trap == 1'b1 && TRAP_PSR_EN == 1'b1) begin
			tto[6:0] = TT_IINST;
			nodaex = '1 & MMUEN;
		end
		else if (t.align_trap == 1'b1) begin 
			tto[6:0] = TT_UNALA;
			nodaex = '1 & MMUEN;	
		end
		//Todo : FP exception here
//		else if (t.daex_trap == 1'b1) //data access exception (MMU exception), not TLB miss!
//			tto[6:0] = TT_DAEX;
    else if (t.ieee754_trap == 1'b1 && FPEN == 1'b1)
      tto[6:0] = TT_FPEXC;
		else if (t.tag_trap == 1'b1 && NOTAG == 1'b0)
			tto[6:0] = TT_TAG;
		else if (t.divz_trap == 1'b1 && DIVEN == 1'b1)
			tto[6:0] = TT_DIVZ;
		else if (t.ticc_trap == 1'b1)
			tto = {1'b1, alu_res[6:0]};		//tt = {1 , software trap#}
		else if ((t.irl == 15 || t.irl > ts.psr.pil ) && ts.psr.et == 1'b1 && ts.ucmode == 0)	begin 
			tto = {4'b01,t.irl};
			ptrap = '0; irq_trap = '1;
		end
		else
			ptrap = '0;
	end
	
	trap_res.precise_trap = ptrap;	
	trap_res.nodaex = nodaex;
	trap_res.irq_trap = irq_trap;
	trap_res.tbr_tt = tto; 	
	
	return trap_res;
endfunction

module memory_stage #(parameter INREG = 1) (input iu_clk_type gclk, input bit rst, 
		    input  mem_reg_type 	       memr,
//		    input  bit [3:0] 		         irl,			       //irq request level
        input  io_bus_out_type      io_in,
        output io_bus_in_type       io_out,
		    input  dcache_data_out_type dcache_data,		//from dcache
		    output dcache_iu_in_type 	  iu2dcache,		  //to dcache
		    output dmmu_iu_in_type 	    iu2dmmu,		    //to dmmu
		    output xc_reg_type 		       xcr);

	typedef struct {				//internal pipeline register type		
		detected_trap_type	trap;		         //trap & IRQs
		
		bit                io_op;          //IO operations

		//untouched signals
		bit			             invalid;	
		thread_state_type	 ts;	
		bit			             branch_true;
		bit [31:0]		       ex_res;
		bit [63:0]         fp_ex_res;
		bit [31:0]		       store_data;
		bit			             annul_next;		
	}memory_delay_reg_type;
	
	//registers
	memory_delay_reg_type	delr, delrin;			  //internal pipeline register
	(* syn_preserve = 1 *) 	xc_reg_type 				xcr_r;	   			  //mem-exception pipeline register
	xc_reg_type 		        xcv;	  			  //mem-exception pipeline register

	//wires
	bit			                signext;	    //no use for st.
	bit	[3:0]		           byte_mask;
	bit [31:0]            store_data;

  bit                   memacc_valid;   //mem-$ access is valid (not including I/O)
  bit                   ioacc_valid;    //valid IO access;
  	
	LDST_CTRL_TYPE			     ldst;	

  
	always_comb begin		//first cycle combinatorial logic
    //signals required by IO read
    io_out.tid  = memr.ts.tid;
    io_out.addr = (INREG) ? memr.ex_res : memr.adder_res;
        
		//generate new traps
		delrin.trap.align_trap = detect_unalign_exception(memr.ts.inst, (INREG) ? memr.ex_res : memr.adder_res) & ~memr.ts.ucmode;
		delrin.trap.psr_trap   = (TRAP_PSR_EN == 1'b1)? detect_psr_exception(memr.ts.inst, (INREG) ? memr.ex_res : memr.adder_res) : '0; 
		
		//forward old traps from previous stage
		delrin.trap.tag_trap  = memr.tag_trap;
		delrin.trap.divz_trap =	memr.divz_trap;
		delrin.trap.ticc_trap = memr.ticc_trap;
		delrin.trap.ieee754_trap = memr.ieee754_trap;
		delrin.trap.tt        = memr.tt;
		delrin.trap.trap      = memr.trap;
		delrin.trap.irl       = io_in.irl;
		
  		//untouched signals
		delrin.ts = memr.ts;
		delrin.invalid = memr.invalid;
		delrin.branch_true = memr.branch_true;
		delrin.annul_next = memr.annul_next;	
		delrin.ex_res = memr.ex_res;
		delrin.fp_ex_res = memr.fp_ex_res;
		delrin.store_data = memr.store_data;


    //decode_asi(memr.ts.inst, delrin.ldst_a, delrin.asi);
    
    //decode IO operations
    delrin.io_op = (memr.ts.ldst_a == 1'b1 && memr.ts.asi == ASI_TIO) ? 1'b1 : '0;
   
		//interface to dcache
		iu2dcache.m1.tid    = memr.ts.tid;
		iu2dcache.m1.va     = (INREG) ? memr.ex_res[31:2] : memr.adder_res[31:2];
//		iu2dcache.m1.ldst_a = memr.ts.ldst_a;
//		iu2dcache.m1.asi    = memr.ts.asi;

		//interface to dmmu		
		//iu2dmmu.m1.tid    = delr.ts.tid;
		iu2dmmu.m1.tid	= memr.ts.tid;
		iu2dmmu.m1.va     = (INREG) ? memr.ex_res : memr.adder_res;
    iu2dmmu.m1.ldst_a = memr.ts.ldst_a;
    iu2dmmu.m1.asi    = memr.ts.asi;

	end

	always_comb begin				//second cycle combinatorial logic 				
		//---------------------interface to dcache---------------------------
		//prepare store data
    store_data = store_alignment(delr.ts.inst, delr.ex_res, delr.store_data);
		iu2dcache.m2.store_data = store_data;
		//--------------------decode ld/st control----------------------------
		//prepare ldst mask (used by st) & signext
		ldst = decode_ldst(delr.ts.inst, delr.ts.ucmode);
		iu2dcache.m2.ldst     = ldst;	

		decode_ldst_mask(delr.ts.inst, delr.ex_res, byte_mask, signext);		
		iu2dcache.m2.byte_mask = byte_mask;

    memacc_valid = ~delr.invalid & (~delr.trap.trap & ~delr.trap.align_trap | delr.ts.ucmode);
    ioacc_valid  = memacc_valid & delr.io_op;
    memacc_valid = memacc_valid & ~delr.io_op;

		iu2dcache.m2.tid        = delr.ts.tid;
		iu2dcache.m2.tid_parity = delr.ts.tid_parity;
		iu2dcache.m2.valid      = memacc_valid;
		iu2dcache.m2.va         = delr.ex_res[31:2];		
//		iu2dcache.m2.replay     = delr.ts.replay;
//		iu2dcache.m2.ldst_a     = delr.ts.ldst_a;
//		iu2dcache.m2.asi        = delr.ts.asi;
		iu2dcache.m2.dma_mode   = delr.ts.dma_mode;
		iu2dcache.m2.atomic     = is_atomic(delr.ts);
		iu2dcache.m2.no_ldreplay = no_ldreplay(delr.ts);
				
		//---------------------interface to dmmu---------------------------
		iu2dmmu.m2.tid    = delr.ts.tid;		
		iu2dmmu.m2.va     = delr.ex_res;
		iu2dmmu.m2.su     = delr.ts.psr.s;
		iu2dmmu.m2.replay = delr.ts.replay;
		iu2dmmu.m2.valid  = memacc_valid;
		iu2dmmu.m2.ldst   = ldst;
		iu2dmmu.m2.ldst_a = delr.ts.ldst_a;
    iu2dmmu.m2.asi    = delr.ts.asi;
    iu2dmmu.m2.dma_mode = delr.ts.dma_mode;
    
    
    //--------------------interface to I/O (write)----------------------
    io_out.wdata = store_data;
    io_out.rw = (ldst == c_ST)? '1 : '0;
    io_out.en = ioacc_valid;
    io_out.replay = delr.ts.replay;
    io_out.we = byte_mask;
    
    
    //--------------------interface to exception stage-------------------
		xcv.invalid     = delr.invalid; 
		xcv.annul_next  = delr.annul_next;
		xcv.branch_true = delr.branch_true;
		xcv.ex_res      = delr.ex_res;	
		xcv.fp_ex_res   = delr.fp_ex_res;
		
		xcv.ts        = delr.ts;			   
		xcv.mem_res   = dcache_data;
		xcv.io_res    = unsigned'(io_in.rdata); 
		xcv.io_op     = delr.io_op; 
		xcv.signext   = signext;			   //for lds*
		xcv.byte_mask = byte_mask;		  //for load align

		xcv.trap_res  = pre_exception(delr.ts, delr.trap, delr.ex_res);		//all exceptions are final except 'DAEX'	
	end


	assign xcr = xcr_r;
/*		
	always @(posedge gclk.clk) begin
		delr = delrin;		//internal pipeline register
		if (rst == 1'b1) begin
			delr.ts.run = '0;
			delr.invalid = '1;
		end		
							
		xcr_r = xcv;
		if (rst == 1'b1)	//mem-exception pipeline register
			xcr_r.ts.run = '0;
	end
*/
  function automatic xc_reg_type get_xcr();
`ifndef SYNP94
    xc_reg_type  xcr_ret = xcv;
`else
    xc_reg_type  xcr_ret;
    xcr_ret = xcv;
`endif    

    if (rst == 1'b1)
      xcr_ret.ts.run = '0;
    
    if (ldst != NOMEM) 
//    if (ioacc_valid)
      xcr_ret.ts.replay = io_in.retry;   //use replay signal from dcache for LD/ST, io_in.retry must be 0
      
    return xcr_ret;
  endfunction
  
  function automatic memory_delay_reg_type get_delr();    
`ifndef SYNP94
    memory_delay_reg_type delr_ret = delrin;		
`else
    memory_delay_reg_type delr_ret;		
    delr_ret = delrin;		
`endif

    if (rst == 1'b1) begin
      delr_ret.ts.run = '0;
      delr_ret.invalid = '1;
    end		

    return delr_ret;
  endfunction
  
  always_ff @(posedge gclk.clk) begin
    xcr_r <= get_xcr();        //mem-exception pipeline register
    delr <= get_delr();       //internal pipeline register
  end
    
endmodule