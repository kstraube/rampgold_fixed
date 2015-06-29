//---------------------------------------------------------------------------   
// File:        alu.v
// Author:      Zhangxi Tan
// Description: ALU stage, implemented using DSPs
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libfp::*;
import libmmu::*;
import libxalu::*;
import libopcodes::*;
import libstd::*;
`else
`include "libiu.sv"
`include "libxalu.sv"
`include "libmmu.sv"
`endif


//Handle RDPSR, RDWIM, RDY
//WRPSR, WRWIM will be handled in WB stage ; RD/WRTBR and RD/WRASR is handled by ALU_add;
task automatic reg_misc_op(input thread_state_type ts, input bit adder_valid, output bit [31:0] miscout, output bit misc_valid);
	`ifndef SYNP94
	bit [1:0]  op    = ts.inst[31:30];
	bit [5:0]  op3   = ts.inst[24:19];

	logic [31:0] res   = '0;
	bit        valid = '0;
	`else
	bit [1:0]  op;
	bit [5:0]  op3;

	logic [31:0] res;
	bit        valid;
	
	op    = ts.inst[31:30];
	op3   = ts.inst[24:19];

	res   = '0;
	valid = '0;
	`endif
		
	if (op == FMT3) begin
		unique case (op3)	
    RDY   : begin
              res[31:0] = ts.y.y;
              
              if (adder_valid == 1'b0)    //not RDASR
                valid = '1;               
            end
		RDPSR : begin 
          		res[31:5]      = {PSR_IMPL, PSR_VER, ts.psr.icc, 6'b0, CPEN, ts.psr.ef, ts.psr.pil, ts.psr.s, ts.psr.ps, ts.psr.et}; 
		        res[NWINMSB:0] = ts.psr.cwp;
		        valid = '1; 
          		end
		RDWIM : begin res[NWIN-1:0] = ts.wim; valid = '1; end
		default : begin 
		            res   = 'x;
		            valid = '0;
		          end
		endcase
	end
	
	miscout = res; misc_valid = valid & (~ts.annul | (ts.dma_mode & ADVDEBUGDMA));	
endtask

  
module	execution_stage #(//parameter int DSPINREG = 1
			parameter DSPINREG = 1,
			parameter DOREG	= 1,
			parameter FASTMUL = 0
)		//ALU DSP has internal input register 
	(input  iu_clk_type gclk, input bit rst, 
	 input 	ex_reg_type 		        exr, 
	 output mem_reg_type 		       memr,
	 //output to dmmu
	 output 	mmu_iu_dtlb_type      iu2dtlb,		
	 //parities
 	 output bit 			               bramerr, 
	 output bit 			               luterr);		//execution stage

	bit [31:0]         raw_alu_res;
  //alu select from adder dsp, mulshf/div dsp, reg misc
	bit 			             misc_valid; 

	xalu_dsp_in_type   	xalu_in;			          //mul/shf/div input	
	alu_dsp_out_type   	adder_res, mul_res;		//dsp output
           
	bit			              mul_replay;			       //replay bit from xalu		

	bit [31:0]          misc_res;		          //misc result RDPSR, RDWIM
	
	bit                 fpu_replay;          //replay bit from fpu
  fpu_in_type         fpu_in;              //input to FPU block
  fpu_out_type        fpu_res;             //output from FPU block
  bit                 fpu_fpop_res_valid, fpu_fcmp_res_valid; 

	//internal pipeline registers
	typedef struct{
		//bit [31:0]		      inst;		     // instruction
		thread_state_type	ts;		       // thread state			
		bit               mul_valid;  // mul/div operation
		bit               fpu_valid;  // fpu operation
		//passed controls from decode stage
		bit			            annul_next;	// annul next instruction (by BICC)		
		bit			            branch_true;// branch (for TICC)
		//decode result	from reg stage
		bit			            wicc;		     // update icc field	
		bit               wy;         // update Y register
		bit [31:0]		      store_data;	// data for ST, address is from ALU

		//detected trap
		trap_type		       tt;
		bit			            trap;		     // trap is detected after register access stage
		bit			            ticc_trap;	 // ticc trap
		//parity 
		bit			            parity;
		
		//input registers if don't use DSP input registers, used for parity calculation (probably shared with regs in DSP adder)
		bit [31:0]        rop1, rop2;

		immu_data_type	immu_data;
	}ex_delay_reg_type;
	
	//(* syn_keep=1 *) ex_delay_reg_type delr;	//delay register
	ex_delay_reg_type   delr;	                 //delay register
  //wire [31:0]         rop1, rop2;            //wires to walk around synthesis

	//standard pipeline register
	//mem_reg_type        mr, mrin;	 //mem stage 
	mem_reg_type          mrin, r_mrin;	 //mem stage 

  //Systemverilog P1800-2005 workaround
   xalu_in_fifo_type    xalu_ififo_data; 
   bit					xalu_op2zero;
  
	//assign memr    = mr;			        //output 
	assign bramerr = delr.parity;		//bram parity error	
	assign luterr  = mul_res.parity_error;

	//interface to mul/shf/div	
  assign xalu_in.replay     = exr.ts.replay;
  assign xalu_in.y          = exr.ts.y;
  assign xalu_in.valid      = exr.mul_valid;
  assign xalu_in.ififo_data.op1_parity = exr.op1_parity;
  assign xalu_in.ififo_data.op2_parity = (LUTRAMPROT)? ^xalu_ififo_data.op2 : '0; //this can be optimized
  assign xalu_in.ififo_data.tid        = exr.ts.tid;	
  
  //Systemverilog P1800-2005 workaround
  assign  xalu_in.ififo_data.op1         = xalu_ififo_data.op1;
  assign  xalu_in.ififo_data.op2         = xalu_ififo_data.op2;
  assign  xalu_in.ififo_data.mode        = xalu_ififo_data.mode;
  assign  xalu_in.ififo_data.misc_parity = xalu_ififo_data.misc_parity;		
  assign  xalu_in.op2zero				 = xalu_op2zero;
  
  generate
    if (FPEN) begin
      assign fpu_in.replay      = exr.ts.replay;
      assign fpu_in.op1         = {exr.fpudata.op1, exr.fpudata.op2};
      assign fpu_in.op2         = {exr.fpudata.op3, exr.fpudata.op4};
      assign fpu_in.fp_op       = exr.fpudata.fp_op;
      assign fpu_in.sp_ops      = exr.fpudata.sp_ops;
      assign fpu_in.sp_result   = exr.fpudata.sp_result;
      assign fpu_in.tid         = exr.ts.tid;
    end
  endgenerate

  
  generate
		if (DSPINREG) begin
			always_ff @(posedge(gclk.clk)) begin		//generate pipeline register for mul/shf/div      
        xalu_ififo_data.op1         <= exr.aludata.op1;
        xalu_ififo_data.op2         <= exr.aludata.op2;
        xalu_ififo_data.mode        <= exr.aludata.msd.mode;
        xalu_ififo_data.misc_parity <= exr.aludata.msd.parity;			
                xalu_op2zero		<= exr.aludata.msd.op2zero;
			end			
		end
		else begin
			assign xalu_ififo_data.op1    = exr.aludata.op1;
			assign xalu_ififo_data.op2    = exr.aludata.op2;
			assign xalu_ififo_data.mode   = exr.aludata.msd.mode;
			assign xalu_ififo_data.misc_parity = exr.aludata.msd.parity;		
			assign xalu_op2zero		= exr.aludata.msd.op2zero;
		end	
	endgenerate

	always_comb begin		//second cycle comb
		//no change part
		mrin.ts          = delr.ts;
		mrin.annul_next  = delr.annul_next;
		mrin.branch_true = delr.branch_true;
		mrin.tt          = delr.tt;
		mrin.trap        = delr.trap;
		mrin.ticc_trap   = delr.ticc_trap;
		mrin.fp_ex_res   = '0;
    mrin.ieee754_trap = '0;
		mrin.immu_data	= delr.immu_data;
		
		//prepare ld/st control
		mrin.store_data = delr.store_data;

		//traps 
		//tag_trap
		mrin.tag_trap = adder_res.tag_overflow & adder_res.valid;
		
		//divide zero trap goes here
		mrin.divz_trap = mul_res.divz & mul_res.valid;
		
		//probably move to previous pipeline stage 
		//reg_misc_op(delr.ts, exr.adder_valid, misc_res, misc_valid);
		reg_misc_op(delr.ts, adder_res.valid, misc_res, misc_valid);
	

		unique case({adder_res.valid, misc_valid, mul_res.valid})		
		3'b100: begin 
				mrin.ex_res = adder_res.result;
				if (delr.wicc & ~adder_res.tag_overflow)
					mrin.ts.psr.icc = adder_res.flag;
			end	
		3'b010: mrin.ex_res = misc_res;
		3'b001: begin 
				mrin.ex_res = mul_res.result;

				if (delr.wicc & ~mul_res.divz)
					mrin.ts.psr.icc = mul_res.flag;
				
				if (delr.wy & ~mul_res.divz)
				  mrin.ts.y = mul_res.y;
				  				
			end
		default: begin 
		          mrin.ex_res = adder_res.result;
		          //synthesis translate_off
              //if ((adder_res.valid | misc_valid | mul_res.valid) & delr.ts.run)
              //  $display("something wrong with the alu result mux [adder, misc, mul] = [%d, %d, %d]", adder_res.valid, misc_valid, mul_res.valid);
		          //synthesis translate_on
		         end
		endcase		
  
  		mrin.adder_res = adder_res.result;
		mrin.invalid = ~(adder_res.valid | misc_valid | mul_res.valid);

    if (delr.mul_valid)
       mrin.ts.replay = mul_replay;
       
    if (FPEN) begin
      
        if (delr.fpu_valid)
          mrin.ts.replay = fpu_replay;
          
	      mrin.fp_ex_res   = fpu_res.fpop_result.result;
        mrin.ieee754_trap = '0;
	     
	      // FP exception handling
	      if (~delr.trap & (fpu_fpop_res_valid | fpu_fcmp_res_valid)) begin 
	        mrin.ts.fsr.cexc[FPEXC_DZBIT] = '0;
	        mrin.ts.fsr.cexc[FPEXC_NXBIT] = '0;
	        if (fpu_fpop_res_valid) begin
	          mrin.ts.fsr.cexc[FPEXC_NVBIT] = fpu_res.fpop_result.invalid_op;
	          mrin.ts.fsr.cexc[FPEXC_OFBIT] = fpu_res.fpop_result.overflow;
	          mrin.ts.fsr.cexc[FPEXC_UFBIT] = fpu_res.fpop_result.underflow;
	        end
	        else begin
             mrin.ts.fsr.cexc[FPEXC_NVBIT] = fpu_res.fcmp_result.invalid_op;
             mrin.ts.fsr.cexc[FPEXC_OFBIT] = '0;
             mrin.ts.fsr.cexc[FPEXC_UFBIT] = '0;
          end
           
	        if (|(mrin.ts.fsr.cexc & mrin.ts.fsr.tem)) begin
	          mrin.ts.fsr.ftt = FTT_IEEE754;
	          mrin.ieee754_trap = '1;
	        end
	        else begin
	          mrin.ts.fsr.aexc = mrin.ts.fsr.aexc | mrin.ts.fsr.cexc;
	          if (fpu_fcmp_res_valid) begin
	            unique case(fpu_res.fcmp_result.cc)
	            4'b0001: mrin.ts.fsr.fcc = 2'b00;
	            4'b0010: mrin.ts.fsr.fcc = 2'b01;
	            4'b0100: mrin.ts.fsr.fcc = 2'b10;
	            4'b1000: mrin.ts.fsr.fcc = 2'b11;
	            default:;
	            endcase
	          end	  	             
          end
       end 
    end         
       
		//if BRAM parity error, stop, regfile sucks
		//TODO: add lutram automatic recovery
		if ((BRAMPROT == 1 && delr.parity == 1'b1) || (LUTRAMPROT ==1 && mul_res.parity_error == 1'b1))
			mrin.ts.run = 1'b0;
	   
	 //to dtlb
   iu2dtlb.tid     = exr.ts.tid;
   iu2dtlb.vpn_tag = raw_alu_res[31:DTLBTAGLSB];
   iu2dtlb.index   = raw_alu_res[DTLBINDEXMSB:DTLBINDEXLSB];
   iu2dtlb.index1  = raw_alu_res[18 +: log2x(NDTLBENTRY)];
   iu2dtlb.ctx     = exr.immu_data.ctx_reg;  		
 		

		//output 
   memr = (DOREG) ? r_mrin : get_mr();
		
	end
	
	//synthesis translate_off
  always_ff @(posedge gclk.clk) begin 
       if (((adder_res.valid & misc_valid) | (mul_res.valid & misc_valid) | (adder_res.valid & mul_res.valid)) & delr.ts.run)
            $display("something wrong with the alu result mux [adder, misc, mul] = [%d, %d, %d]", adder_res.valid, misc_valid, mul_res.valid);
  end
	//synthesis translate_on
	
/*
  assign rop1 = delr.rop1;
  assign rop2 = delr.rop2;
  
	always @(posedge(gclk.clk)) begin
		//internl pipeline registers
		#360ps mr = mrin;
		
		if (rst == 1'b1)
			mr.ts.run = '0;		
							
		delr.ts = exr.ts;
		if (rst == 1'b1)
			delr.ts.run = '0;

		delr.annul_next  = exr.annul_next;
		delr.branch_true = exr.branch_true;
		delr.wicc        = exr.wicc;
		delr.wy          = exr.wy;
		delr.store_data  = exr.store_data;
		delr.tt          = exr.tt;
		delr.trap        = exr.trap;		
		delr.ticc_trap   = exr.ticc_trap;		
    delr.mul_valid   = exr.mul_valid;

		//software parity check;
		if (BRAMPROT) begin
		  if (DSPINREG) begin
    		  delr.rop1 = exr.aludata.op1;
		    delr.rop2 = exr.aludata.op2;
      
        //delr.rop1 <= exr.aludata.op1;
        //delr.rop2 <= exr.aludata.op2;
          
        //assert ( ((^delr.rop1 ^ exr.op1_parity) & !exr.ign_op1_seu) == 0);
        //assert ( ((^delr.rop2 ^ exr.op2_parity) & !exr.ign_op2_seu) == 0);

        //delr.parity = ((^delr.rop1 ^ exr.op1_parity) & !exr.ign_op1_seu) | ((^delr.rop2 ^ exr.op2_parity) & !exr.ign_op2_seu);  

        //synthesis translate_off
        assert ( ((^rop1 ^ exr.op1_parity) & !exr.ign_op1_seu) == 0) else $display("@%t op1 parity error", $time);
        assert ( ((^rop2 ^ exr.op2_parity) & !exr.ign_op2_seu) == 0) else $display("@%t op2 parity error", $time);        
        //synthesis translate_on
        
        delr.parity = ((^rop1 ^ exr.op1_parity) & !exr.ign_op1_seu) | ((^rop2 ^ exr.op2_parity) & !exr.ign_op2_seu);  
      end
		  else begin
		    delr.rop1 = '0;   //unused
		    delr.rop2 = '0;   //unused
		    
		    //delr.rop1 <= '0;   //unused
        //delr.rop2 <= '0;   //unused
        
		    delr.parity = (((^exr.aludata.op1[31:0]) ^ exr.op1_parity) & !exr.ign_op1_seu) |
				       (((^exr.aludata.op2[31:0]) ^ exr.op2_parity) & !exr.ign_op2_seu);  
			end
    end
	end
*/
  
  //synthesis translate_off   
  property p1;
   @(posedge(gclk.clk)) 
    disable iff (rst || DSPINREG == 0) 
        (((^delr.rop1 ^ exr.op1_parity) & ~exr.ign_op1_seu) == 0);
  endproperty
  
  property p2;
   @(posedge(gclk.clk))
    disable iff (rst || DSPINREG == 0) 
        (((^delr.rop2 ^ exr.op2_parity) & ~exr.ign_op2_seu) == 0);
  endproperty
  
  property p3;
   @(posedge(gclk.clk)) 
    disable iff (rst || DSPINREG == 1) 
        (((^exr.aludata.op1 ^ exr.op1_parity) & ~exr.ign_op1_seu) == 0);
  endproperty
  
  property p4;
   @(posedge(gclk.clk))
    disable iff (rst || DSPINREG == 1) 
        (((^exr.aludata.op2 ^ exr.op2_parity) & ~exr.ign_op2_seu) == 0);
  endproperty

`ifdef FPEN
  property p5;
    @(posedge(gclk.clk)) 
      disable iff (rst) 
      ((^exr.fpudata.op1 ^ exr.fpudata.op1_parity) == 0);
  endproperty
  
  property p6;
    @(posedge(gclk.clk))
      disable iff (rst) 
      ((^exr.fpudata.op2 ^ exr.fpudata.op2_parity) == 0);
  endproperty 
        
  property p7;
    @(posedge(gclk.clk)) 
      disable iff (rst) 
      ((^exr.fpudata.op3 ^ exr.fpudata.op3_parity) == 0);
  endproperty
  
  property p8;
    @(posedge(gclk.clk))
      disable iff (rst) 
      ((^exr.fpudata.op4 ^ exr.fpudata.op4_parity) == 0);        
  endproperty
`endif

  assert property(p1) else $display("@%t op1 parity error", $time);
  assert property(p2) else $display("@%t op2 parity error", $time);        

  assert property(p3) else $display("@%t op1 parity error", $time);
  assert property(p4) else $display("@%t op2 parity error", $time);
  
`ifdef FPEN
  assert property(p5) else $display("@%t FP op1 parity error", $time);
  assert property(p6) else $display("@%t FP op2 parity error", $time); 
  assert property(p7) else $display("@%t FP op3 parity error", $time);
  assert property(p8) else $display("@%t FP op4 parity error", $time); 
`endif
    
  //synthesis translate_on


  function automatic ex_delay_reg_type get_delr();
    ex_delay_reg_type delr_ret;
  
    delr_ret.ts = exr.ts;
    if (rst == 1'b1)
      delr_ret.ts.run = '0;
  
    delr_ret.annul_next  = exr.annul_next;
    delr_ret.branch_true = exr.branch_true;
    delr_ret.wicc        = exr.wicc;
    delr_ret.wy          = exr.wy;
    delr_ret.store_data  = exr.store_data;
    delr_ret.tt          = exr.tt;
    delr_ret.trap        = exr.trap;		
    delr_ret.ticc_trap   = exr.ticc_trap;		
    delr_ret.mul_valid   = exr.mul_valid;
    delr_ret.immu_data   = exr.immu_data;

    if (FPEN)
      delr_ret.fpu_valid   = exr.fpudata.fp_op != FP_NONE;
    else
      delr_ret.fpu_valid   = '0;
  
    //software parity check;
    if (BRAMPROT) begin
       if (DSPINREG) begin
          delr_ret.rop1 = exr.aludata.op1;
          delr_ret.rop2 = exr.aludata.op2;
                        
          delr_ret.parity = ((^delr.rop1 ^ exr.op1_parity) & ~exr.ign_op1_seu) | ((^delr.rop2 ^ exr.op2_parity) & ~exr.ign_op2_seu);  
        end
        else begin
          delr_ret.rop1 = '0;   //unused
          delr_ret.rop2 = '0;   //unused          
          
          delr_ret.parity = (((^exr.aludata.op1[31:0]) ^ exr.op1_parity) & ~exr.ign_op1_seu) |
                 (((^exr.aludata.op2[31:0]) ^ exr.op2_parity) & ~exr.ign_op2_seu);  
        end
        if (FPEN)
          delr_ret.parity |= ( ((^exr.fpudata.op1) ^ exr.fpudata.op1_parity) | ((^exr.fpudata.op1) ^ exr.fpudata.op1_parity) |
                  ((^exr.fpudata.op1) ^ exr.fpudata.op1_parity) | ((^exr.fpudata.op1) ^ exr.fpudata.op1_parity));
    end
    else begin
        delr_ret.rop1 = '0;
        delr_ret.rop2 = '0;
    end
        
    
    return delr_ret;
  endfunction
  
  function automatic mem_reg_type get_mr();
`ifndef SYNP94
    mem_reg_type mr = mrin;
`else
    mem_reg_type mr;
    mr = mrin;
`endif    
    
    if (rst == 1'b1)
      mr.ts.run = '0;		
    
    return mr;    
  endfunction

  //pipeline registers  
	always_ff @(posedge gclk.clk)  delr <= get_delr();
	always_ff @(posedge gclk.clk) if (DOREG)  r_mrin <= get_mr();		
  
	//adder dsp
	alu_adder_logic dsp_adder(.gclk, .rst, .valid(exr.adder_valid),.alu_data(exr.aludata), .alu_res(adder_res), .raw_alu_res);	//adder_res is a multicycle output

	//Mul/div/shf dsp goes here
  generate 
    if (FASTMUL)
     xalu_if_fast	xalu_mul_div(.gclk, .rst, 
                   .xalu_in, 
                   .xalu_out(mul_res), 
                   .new_replay(mul_replay) 
                    );
    else  
    	xalu_if	xalu_mul_div(.gclk, .rst, 
	                 .xalu_in, 
	                 .xalu_out(mul_res), 
	                 .new_replay(mul_replay) 
                    );
  endgenerate
                    
  //FPU
  generate
    if (FPEN)
       fpu_if gen_fpu_if(.gclk, .rst,
                    .fpu_in,
                    .fpu_out(fpu_res),
                    .fpop_valid(fpu_fpop_res_valid),
                    .fcmp_valid(fpu_fcmp_res_valid),
                    .new_replay(fpu_replay)
                    );
  endgenerate
  
endmodule
