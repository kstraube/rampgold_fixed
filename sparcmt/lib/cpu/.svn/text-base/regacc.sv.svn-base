//------------------------------------------------------------------------------ 
// File:        regacc.v
// Author:      Zhangxi Tan
// Description: Functions and modules used in reg stage
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libiu::*;
import libopcodes::*;
import libconf::*;
import libtech::*;
`else
`include "libiu.sv"
`endif

//internal pipeline registers
typedef struct{	
		thread_state_type	ts;		// thread state					
		//passed controls from decode stage
		bit			annul_next;	// annul next instruction (by BICC)		
		bit			branch_true;	// branch (for TICC)
		bit			iaex;		// instruction access exception (MMU exception)
		//decoding result
		bit			wovrf;		// register window overflow
		bit			wundf;		// register window underflow
}reg_delay_reg_type;


//decode fro mul/shf/div
task automatic decode_dsp_mul_div_shf(input reg_delay_reg_type r, output mul_ctrl_type mode, output bit mul_valid, output bit write_y, output bit parity); 
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];	
	bit [5:0] op3 = r.ts.inst[24:19];
  	
	mul_ctrl_type 	gmode = c_UMUL;
    bit            wy = '0;

	bit            valid = '0;
`else
	bit [1:0] op;	
	bit [5:0] op3;
  	
	mul_ctrl_type 	gmode;
    bit            wy;

	bit            valid;

	op  = r.ts.inst[31:30];	
	op3 = r.ts.inst[24:19];
  	
	gmode = c_UMUL;
    wy = '0;

	valid = '0;
`endif
	
	if (op == FMT3) begin
		valid = '1;
		unique case(op3) 
		UMUL : begin gmode = c_UMUL; wy = '1;end 
		SMUL : begin gmode = c_SMUL; wy = '1; end
		UMULCC : begin gmode = c_UMUL; wy= '1; end
		SMULCC : begin gmode = c_SMUL; wy = '1; end
		UDIV : begin gmode = c_UDIV; end
		SDIV : begin gmode = c_SDIV; end
		UDIVCC : begin gmode = c_UDIV; end
		SDIVCC :begin gmode = c_SDIV; end
		ISLL : begin gmode = c_SLL; end
		ISRL : begin gmode = c_SRL; end
		ISRA : begin gmode = c_SRA; end
		default : valid = '0;		//does nothing 			
		endcase
	end
	
	mode = gmode;
	mul_valid = valid;
	write_y = wy;
	
	parity = (LUTRAMPROT)? ^{r.ts.tid_parity, gmode} : '0;
endtask

task automatic decode_dsp_add_logic(input reg_delay_reg_type r, output dsp_ctrl_type dsp_ctrl, output bit carryout, output alu_gen_flag_type flagout, output bit adder_valid);		
//decode DSP control signals (in REG stage? probably moved to decoding stage for resource sharing?)
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [2:0] op2 = r.ts.inst[24:22];
	bit [5:0] op3 = r.ts.inst[24:19];

	bit [4:0] rs1 = r.ts.inst[18:14];

	bit valid = '1; 	//valid by default

	//dsp controls
	dsp_ctrl_type	dspctrl = DSP_ADDC; 	//A:B + C + CIN;
	
	alu_gen_flag_type	dsp_flag = DEFAULTcc;

	bit co	= '0;	//carry input for DSP
`else
	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;

	bit [4:0] rs1;

	bit valid; 	//valid by default

	//dsp controls
	dsp_ctrl_type	dspctrl; 	//A:B + C + CIN;
	
	alu_gen_flag_type	dsp_flag;

	bit co;	//carry input for DSP

	op  = r.ts.inst[31:30];
	op2 = r.ts.inst[24:22];
	op3 = r.ts.inst[24:19];

	rs1 = r.ts.inst[18:14];

	valid = '1; 	//valid by default

	//dsp controls
	dspctrl = DSP_ADDC; 	//A:B + C + CIN;
	
	dsp_flag = DEFAULTcc;

	co	= '0;	//carry input for DSP
`endif

	unique case (op)
	CALL:
		//default A:B + C + CIN; 	
		dspctrl = DSP_ADDC;	
	FMT2: 	unique case(op2)
		SETHI:	//by pass immediate 
			dspctrl = DSP_OP2;	//A:B + 0 + CIN; 				
		BICC, FBFCC, CBCCC:  
			    dspctrl = DSP_ADDC;		//A:B + C + CIN; PC + imm	 
		default: begin 
		          valid ='0; 
		          dspctrl = '{'x, 'x};          
		         end
		endcase 	
	 FMT3:  unique case (op3)			
		IADD, ADDX, ADDCC, ADDXCC, TADDCC, TADDCCTV, SAVE, RESTORE,
		TICC, JMPL, RETT, MULSCC, FLUSH: begin	//ADD 		
						dspctrl = DSP_ADDC; //A:B + C + CIN

						//decode cc here
						if (op3 == ADDX || op3 == ADDXCC) co = r.ts.psr.icc[0];
						
						unique case(op3)
						ADDCC, ADDXCC, ADDXCC, MULSCC: dsp_flag = ADDcc;
						TADDCC  : dsp_flag = TADDcc;
						TADDCCTV: dsp_flag = TADDccTV;
						default : dsp_flag = DEFAULTcc;
						endcase

						end
		ISUB, SUBX, SUBCC, SUBXCC, TSUBCC, TSUBCCTV:	begin		//SUB
								dspctrl = DSP_SUBC;	//C-(A:B + CIN)

								//decode cc here
								if (op3 ==SUBX || op3 == SUBXCC) co = r.ts.psr.icc[0];
							
								unique case(op3)
								SUBCC, SUBXCC: dsp_flag = SUBcc;
								TSUBCC  : dsp_flag = TSUBcc;
								TSUBCCTV: dsp_flag = TSUBccTV;
								default : dsp_flag = DEFAULTcc;
							endcase
								
							end
	
		 IAND, ANDCC :	dspctrl =  DSP_AND;	// A:B and C	
	      	 ANDN, ANDNCC : dspctrl = DSP_ANDN;	// (not A:B) and C		
      		 IOR, ORCC : dspctrl = DSP_OR;		// A:B or C
	      	 ORN, ORNCC : dspctrl = DSP_ORN;	// (not A:B) or C
	      	 IXNOR, XNORCC : dspctrl = DSP_XNOR;	// A:B xnor C
      		 XORCC, IXOR, WRPSR, WRWIM, WRTBR, WRY : dspctrl = DSP_XOR;	// A:B xnor C
		RDY : begin		//RDASR
			if (ASREN == 1) begin //ASR is enabled
				if (rs1 > 0 )   
					valid = '1;
				else begin
				  valid = '0;
          dspctrl = '{'x, 'x};   
				end
					
				dspctrl = DSP_OP1;	// 0 + C + CIN	 		
			end
			else begin
				valid = '0;			
        dspctrl = '{'x, 'x};   
      end				
	  end
		RDTBR : dspctrl = DSP_OP1;	// 0 + C + CIN
		default: begin 
		          valid ='0;
              dspctrl = '{'x, 'x};	          		          
		         end
		endcase
	 LDST:	begin		
		dspctrl = DSP_ADDC;		//The first cycle is always address calculation	A:B + C + CIN	
 		
 		if (r.ts.ucmode == 1'b1 && op3[3:2] == 2'b01)  // pass rs1, ST* in microcode mode has diffrent meanings
			dspctrl = DSP_OP1;	// 0 + C + CIN	;	store address
/*
    unique case(op3)
      LD, LDUB, LDUH, LDD, LDSB, LDSH,	LDSTUB,	SWAP,	LDA,	LDUBA,	LDUHA,	LDDA,	LDSBA,	LDSHA,	LDSTUBA,	SWAPA,
      ST,	STB,	STH,	STD,	STA,	STBA,	STHA,	STDA : valid = '1;
      LDDF, STDF, LDF, LDFSR, STF, STFSR, STDFQ : valid = FPEN;    
      STDCQ, LDC, LDCSR, LDDC, STC, STCSR, STDC : valid = CPEN;
      default : valid = '0;
    endcase
*/    
		end	
	endcase

		
	dsp_ctrl = dspctrl;	
	flagout = dsp_flag;	
	carryout = co;
	adder_valid = valid;
	
endtask

function automatic bit wicc_gen(reg_delay_reg_type r);	//generate new icc
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [5:0] op3 = r.ts.inst[24:19];
	
	bit wicc = '0;
`else
	bit [1:0] op;
	bit [5:0] op3;
	
	bit wicc;

	op  = r.ts.inst[31:30];
	op3 = r.ts.inst[24:19];
	
	wicc = '0;
`endif	

	if (op == FMT3) begin
		unique case(op3)
		SUBCC, TSUBCC, TSUBCCTV, ADDCC, ANDCC, ORCC, XORCC, ANDNCC, MULSCC, ORNCC, 
		XNORCC, TADDCC, TADDCCTV, ADDXCC, SUBXCC, UMULCC, SMULCC, UDIVCC, SDIVCC: wicc = '1;
		default:  wicc = '0;
		endcase
	end

	return wicc;
endfunction


function automatic bit [31:0] imm_data(reg_delay_reg_type r);
`ifndef SYNP94
  bit [31:0] immediate_data = '0;

  bit [1:0] op  = r.ts.inst[31:30];
  bit [2:0] op2 = r.ts.inst[24:22];
  bit [5:0] op3 = r.ts.inst[24:19];
`else
  bit [31:0] immediate_data;

  bit [1:0] op;
  bit [2:0] op2;
  bit [5:0] op3;

  immediate_data = '0;

  op  = r.ts.inst[31:30];
  op2 = r.ts.inst[24:22];
  op3 = r.ts.inst[24:19];
`endif
  
	unique case(op)
	CALL:	immediate_data = {r.ts.inst[29:0],2'b0};
	FMT2:	immediate_data = (op2 == SETHI)? {r.ts.inst[21:0], 10'b0} : {{8{r.ts.inst[21]}}, r.ts.inst[21:0], 2'b0};		
	default: immediate_data = {{19{r.ts.inst[12]}}, r.ts.inst[12:0]};		 
	endcase

	return immediate_data;
endfunction

//op mux for rs1, rfo is the register file output. Select between PC and rfo
task automatic opmux_rs1(input reg_delay_reg_type r, input bit [31:0] rfo, output bit[31:0] aluop, output bit ign_seu);
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [2:0] op2 = r.ts.inst[24:22];
	bit [5:0] op3 = r.ts.inst[24:19];
	
	bit [31:0] aluop1 = rfo;
	bit        no_seu = '0;
`else
	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;
	
	bit [31:0] aluop1;
	bit        no_seu;

	op  = r.ts.inst[31:30];
	op2 = r.ts.inst[24:22];
	op3 = r.ts.inst[24:19];
	
	aluop1 = rfo;
	no_seu = '0;
`endif

	unique case(op)
	CALL: begin aluop1 = {r.ts.pc, 2'b0} ; no_seu = '1; end
	FMT2: begin
	       unique case(op2)
	       BICC, FBFCC, CBCCC: aluop1 = {r.ts.pc, 2'b0};
	       default: aluop1 = rfo;
	       endcase
	       no_seu = '1;
	      end
	FMT3:  aluop1 = (op3 == MULSCC) ? {r.ts.psr.icc.N ^ r.ts.psr.icc.V, rfo[31:1]} :rfo;	      
	LDST: begin
	       aluop1 = rfo;

	       if (r.ts.ucmode == 1 && op3 == STD)   //patch address
	         aluop1[2] = 1'b1;	       
	      end
	endcase

  aluop = aluop1;
  ign_seu = no_seu;
endtask

//op mux for rs2, rfo is the register file output. Select between imm and rfo.
task automatic opmux_rs2(input reg_delay_reg_type r, input bit [31:0] rfo, output bit [31:0] aluop, output bit ign_seu);
`ifndef SYNP94
  	bit [1:0] op  = r.ts.inst[31:30];
  	bit [5:0] op3 = r.ts.inst[24:19];
  	bit       i   = r.ts.inst[13];           //i bit
	
 	bit [31:0] aluop2;
	bit [31:0] imm = imm_data(r);
	bit        no_seu = '0;
`else
  	bit [1:0] op;
  	bit [5:0] op3;
  	bit       i;           //i bit
	
	bit [31:0] aluop2;
	bit [31:0] imm;
	bit        no_seu;

    op  = r.ts.inst[31:30];
    op3 = r.ts.inst[24:19];
    i   = r.ts.inst[13];           //i bit
	
 	imm = imm_data(r);
	no_seu = '0;
`endif	
	
	unique case(op)
	CALL: begin aluop2 = imm; no_seu = '1; end
	FMT2: begin aluop2 = imm; no_seu = '1; end
	FMT3: begin
            if (op3 == MULSCC && r.ts.y.y[0] == 1'b0) begin
              aluop2 = '0; no_seu = '1;
            end
            else begin
              aluop2 = (i == 1'b1)? imm : rfo; no_seu = i;
            end
	      end
	default: begin aluop2 = (i == 1'b1)? imm : rfo; no_seu = i; end
	endcase

	aluop   = aluop2;
	ign_seu = no_seu;
endtask

//generate new y reg (handle MULSCC)
function automatic y_reg_type get_new_y(reg_delay_reg_type r, bit rs1_0);
`ifndef SYNP94
  bit [1:0] op  = r.ts.inst[31:30];
  bit [5:0] op3 = r.ts.inst[24:19];
  
  y_reg_type new_y = r.ts.y;
`else
  bit [1:0] op;
  bit [5:0] op3;
  
  y_reg_type new_y;

  op  = r.ts.inst[31:30];
  op3 = r.ts.inst[24:19];
  
  new_y = r.ts.y;
`endif
   
  if (op == FMT3 && op3 == MULSCC) begin
    new_y.y      = {rs1_0, r.ts.y.y[31:1]};
    new_y.parity =  r.ts.y.parity ^ r.ts.y.y[0] ^ rs1_0;
  end
  
  return new_y;
endfunction


//detect exceptions in register access stage
task automatic exception_detect_reg(input reg_delay_reg_type r, output bit trap, output bit ticc_exception, output trap_type tto); //, output bit execution_mode, output bit error_mode);
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [2:0] op2 = r.ts.inst[24:22];
	bit [5:0] op3 = r.ts.inst[24:19];

	bit rs1 = r.ts.inst[18:14];
	
	bit td = '1;		//trap detected
	trap_type tt = '0;

	bit fp_disabled = '0;
	bit cp_disabled = '0;
	bit illegal_inst = '0;
	bit ticc_trap = '0;
	bit privileged_inst = '0;
`else
	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;

	bit rs1;
	
	bit td;		//trap detected
	trap_type tt;

	bit fp_disabled;
	bit cp_disabled;
	bit illegal_inst;
	bit ticc_trap;
	bit privileged_inst;

	op  = r.ts.inst[31:30];
	op2 = r.ts.inst[24:22];
	op3 = r.ts.inst[24:19];

	rs1 = r.ts.inst[18:14];
	
	td = '1;		//trap detected
	tt = '0;

	fp_disabled = '0;
	cp_disabled = '0;
	illegal_inst = '0;
	ticc_trap = '0;
	privileged_inst = '0;

`endif	
//	bit exe_mode = r.ts.execution_mode;
//	bit err_mode = r.ts.error_mode;

	unique case (op)
	CALL: ;
	FMT2: unique case(op2)
	      SETHI, BICC: ;
	      FBFCC: fp_disabled = !FPEN;
      	      CBCCC: cp_disabled = !CPEN; 
	      default: illegal_inst = '1; 
	      endcase
	FMT3: unique case(op3)
	     IAND, ANDCC, ANDN, ANDNCC, IOR, ORCC, ORN, ORNCC, IXOR,
	     XORCC, IXNOR, XNORCC, ISLL, ISRL, ISRA, MULSCC, IADD, ADDX,
	     ADDCC, ADDXCC, ISUB, SUBX, SUBCC, SUBXCC, FLUSH, JMPL: ; //address trap for jump will be handled after ALU
	     SAVE, RESTORE: ; 
	     RDY, WRY: if (rs1 > 0)  //not rdy
      		   begin	 //All ASRs are privileged
          			if (ASREN == 1) 
          			   	privileged_inst = ~r.ts.psr.s;
          			else
            				illegal_inst = '1;		//RDASR is not supported
        		   end
	     TICC : ticc_trap = r.branch_true; 
      	     TADDCC, TADDCCTV, TSUBCC, TSUBCCTV: if (NOTAG == 1) illegal_inst = '1; 
             UMUL, SMUL, UMULCC, SMULCC : if (MULEN == 0) illegal_inst = '1; 
      	     UDIV, SDIV, UDIVCC, SDIVCC : if (DIVEN == 0) illegal_inst = '1; 
	     RETT : begin 
//		if (r.ts.psr.et == 1'b1)
		illegal_inst = r.ts.psr.et; 		//use LEON style rett trap
		privileged_inst = ~r.ts.psr.s; 		//trap when s=1, et=0 (interrupt handler) as error
		end
      	     RDPSR, RDTBR, RDWIM, WRPSR, WRWIM, WRTBR: privileged_inst = ~r.ts.psr.s;
      	    FPOP1, FPOP2 : fp_disabled = ~FPEN; 
      	    CPOP1, CPOP2 : cp_disabled = ~CPEN; 
      	    default : illegal_inst = '1;
	    endcase
	LDST: unique case(op3)
	      LDD, STD: illegal_inst = r.ts.inst[25]; // trap if odd destination register
      	      LD, LDUB, LDSTUB, LDUH, LDSB, LDSH, ST, STB, STH, SWAP: ;
      	      LDDA, STDA : begin
			   illegal_inst = r.ts.inst[13] | r.ts.inst[25]; //rd[0] = 1 or i = 1
			   privileged_inst = ~r.ts.psr.s;			   
			   end
      	      LDA, LDUBA, LDSTUBA, LDUHA, LDSBA, LDSHA, STA, STBA, STHA, SWAPA : begin		
			  illegal_inst = r.ts.inst[13]; 
			  privileged_inst = ~r.ts.psr.s;
			  end
      	      LDDF, STDF, LDF, LDFSR, STF, STFSR : fp_disabled = !FPEN;
      	      STDFQ : begin 
			privileged_inst = ~r.ts.psr.s;
			fp_disabled = ~FPEN; 
		     end
      	      STDCQ : begin 
			privileged_inst = ~r.ts.psr.s;
			cp_disabled = ~CPEN; 
		      end
      	      LDC, LDCSR, LDDC, STC, STCSR, STDC : cp_disabled = ~CPEN;
	      default : illegal_inst = '1;
      	      endcase
	endcase

	//follow SPARC exception priority
	if (r.iaex == 1'b1 && MMUEN == 1) tt = TT_IAEX;
    	else if (privileged_inst) tt = TT_PRIV; 
    	else if (illegal_inst == 1'b1 && TRAP_IINST_EN == 1'b1) tt = TT_IINST;
    	else if (fp_disabled) tt = TT_FPDIS;
    	else if (cp_disabled) tt = TT_CPDIS;
	   else if (r.wovrf) tt = TT_WINOF;
    	else if (r.wundf) tt = TT_WINUF;
//    	else if (ticc_trap = 1'b1) tt = TT_TICC;
    	else td = '0; 
	
	ticc_exception = ticc_trap;
	trap = td;
	tto = tt;
endtask

//rst must be clocked
//module regacc_stage #(parameter int DSPINREG = 1)			//ALU DSP has internal input register 
module regacc_stage #(parameter DSPINREG = 1)			//ALU DSP has internal input register 
(input iu_clk_type gclk, input bit rst, 
	input 	reg_reg_type 	regr, 
	input 	commit_reg_type comr, 
	output 	ex_reg_type 	exr
	);	
	//clock 2x signals
	//bit rst2x;				//shape rst2x to synchronize with clk1x 	
	
	//BRAM register interface
	regfile_read_in_type	 rfi;
	regfile_read_out_type	rfo;
	
	//clock 1x signals
	ex_reg_type erin, er;	
	bit [31:0] op1_d, op2_d;			
	bit [6:0]  op1_parity_d, op2_parity_d;
	
	bit adder_valid, mul_valid;
	
	//(* syn_keep=1 *) reg_delay_reg_type delr1, delr2;	//delay register
	reg_delay_reg_type delr1, delr2;	//delay register
								//try to use physical synthesis to remove one stage later
								
	always_comb begin
		//no change part
		erin.ts = delr2.ts;		
		erin.annul_next = delr2.annul_next;
		erin.branch_true = delr2.branch_true;
    
		//clock 1x logic
		decode_dsp_add_logic(delr2, erin.aludata.al.dsp_ctrl, erin.aludata.carryin, erin.aludata.al.genflag, adder_valid);		     //decode adder/logic
		erin.adder_valid = adder_valid & ~delr2.ts.annul;
		
		decode_dsp_mul_div_shf(delr2, erin.aludata.msd.mode, mul_valid, erin.wy, erin.aludata.msd.parity);		                     //decode mul/shf/div
		erin.mul_valid = mul_valid & ~delr2.ts.annul;
		
		opmux_rs1(delr2, op1_d, erin.aludata.op1[31:0], erin.ign_op1_seu);
		opmux_rs2(delr2, op2_d, erin.aludata.op2[31:0], erin.ign_op2_seu);		//op
				
		erin.store_data = op2_d;    //write back_data, phy address is stored in op1
		
		//handle MULSCC inst
		erin.ts.y = get_new_y(delr2, op1_d[0]);
		
		
	  if (BRAMPROT) begin

      erin.op1_parity = op1_parity_d[6];	//op parity (default value)

	    unique case(delr2.ts.inst[31:30])
	    FMT3 : begin 
	             if (delr2.ts.inst[24:19] == MULSCC)
	          		   erin.op1_parity = op1_parity_d[6] ^ op1_d[0] ^ delr2.ts.psr.icc.N ^ delr2.ts.psr.icc.V;
	          	end
	    LDST : begin
	             if (delr2.ts.inst[24:19] == STD && delr2.ts.ucmode == 1)
                 erin.op1_parity = op1_parity_d[6] ^ op1_d[2] ^ 1'b1;
             end
      default: erin.op1_parity = op1_parity_d[6];
      endcase
                
		  erin.op2_parity = op2_parity_d[6];
		end
		else begin
		  erin.op1_parity = '0;
		  erin.op2_parity = '0;
		end
			
		erin.wicc = wicc_gen(delr2);					//write icc?
		exception_detect_reg(delr2, erin.trap, erin.ticc_trap, erin.tt);	//exception detection

		//erin.mul_valid = erin.mul_valid & (!delr2.ts.annul_trap | delr2.ts.ucmode ) & delr2.ts.run;
		//erin.mul_valid = erin.mul_valid & ~delr2.ts.annul  & delr2.ts.run;
		erin.mul_valid = erin.mul_valid & ~delr2.ts.annul;
	end
	
	//output
	always_comb begin
		exr = er;		
		if (DSPINREG) begin		//ALU DSP has input register, then we don't need extra registers
			exr.aludata = erin.aludata;
		end
	end
	
/*
	always @(posedge gclk.clk) begin
		//rst2x <= rst;			//shape clk2x reset signal

		//delay register		
		delr1.ts <= regr.ts;
		delr1.annul_next <= regr.annul_next; 
		delr1.branch_true <= regr.branch_true;
		delr1.iaex <= regr.iaex;
		delr1.wovrf <= regr.wovrf;
		delr1.wundf <= regr.wundf;		
		
		delr2 <= delr1;

		//registers cross two clock domains
		op1_d <= rfo.op1_data; 
		op2_d <= rfo.op2_data;
		op1_parity_d <= rfo.op1_parity;     
		op2_parity_d <= rfo.op2_parity;

		//pipeline register
		er = erin;
		if (rst) begin 
			er.ts.run = '0;
			er.mul_valid = '0;
			er.adder_valid = '0;
			er.aludata.msd.mode = c_NOP;	//don't care
			er.aludata.msd.parity = '0;
		end
	end
*/

function automatic ex_reg_type get_er();
`ifndef SYNP94
  ex_reg_type er_ret = erin;
`else
  ex_reg_type er_ret;
  er_ret = erin;
`endif  
  
  if (rst) begin 
    er_ret.ts.run             = '0;
    er_ret.mul_valid          = '0;
    er_ret.adder_valid        = '0;
    er_ret.aludata.msd.mode   = c_NOP;	//don't care
    er_ret.aludata.msd.parity = '0;
  end

  return er_ret;
endfunction

always_ff @(posedge gclk.clk) begin
    //delay register		
    delr1.ts          <= regr.ts;
    delr1.annul_next  <= regr.annul_next; 
    delr1.branch_true <= regr.branch_true;
    delr1.iaex        <= regr.iaex;
    delr1.wovrf       <= regr.wovrf;
    delr1.wundf       <= regr.wundf;		
  
    delr2 <= delr1;

    //registers cross two clock domains
    op1_d        <= rfo.op1_data; 
    op2_d        <= rfo.op2_data;
    op1_parity_d <= rfo.op1_parity;     
    op2_parity_d <= rfo.op2_parity;

    //pipeline register
    er <= get_er();
  end
	
	//regfile input
	assign rfi.op1_addr = regr.rs1;
	assign rfi.op2_addr = regr.rs2;
	
	//integer register file
	regfile iregf(.gclk, .rst, .rfi, .rfo, .rfc(comr.regf));
endmodule 
