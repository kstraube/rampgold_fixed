//---------------------------------------------------------------------------   
// File:        fpalu.v
// Author:      Rimas Avizienis
// Description: interface to FPU functional units (uses coregen FP units)
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libstd::*;
import libiu::*;
import libfp::*;
`else
`include "../cpu/libiu.sv"
`endif

module sh_reg #(parameter WIDTH = 16, DEPTH = 4) (input bit clk, input bit [WIDTH-1:0] din, output bit [WIDTH-1:0] dout);
  (* syn_srlstyle= "select_srl" *) bit [WIDTH-1:0] data [DEPTH-1:0];
  
  integer i;
  always_ff @ (posedge clk) begin
    for (i = (DEPTH-1); i > 0; i = i-1)
      data[i] <= data[i-1];
    data[0] <= din;
  end

  assign dout = data[DEPTH-1];
endmodule

//output data buffer
module  fpu_fpop_output_dbuf #(parameter DOREG=1) 
          (input iu_clk_type gclk,
           input  fpu_fpop_fu_out_type     din,
           input  bit [NTHREADIDMSB:0]	raddr,	//IU read addr
           output fpu_fpop_out_type		     dout	  //read data (to IU)
            );	
            
  (* syn_ramstyle = "select_ram" *)	fpu_fpop_out_type	         obuf[0:NTHREAD-1];	//RAM
  fpu_fpop_out_type	         dor;			//output register

  (* syn_maxfan=8 *) bit [NTHREADIDMSB:0]				waddr;			//TDM write addr
  (* syn_maxfan=8 *) bit						        we;			   //TDM we
  fpu_fpop_out_type					     wdata;			//TDM data

  assign dor = obuf[raddr];

  assign waddr = din.tid;
  assign we    = din.valid;
  assign wdata = din.data;
  generate
    if (DOREG) begin
  //    always_ff @(posedge gclk.clk) begin
  		always_ff @(posedge gclk.clk2x) begin
	     if (gclk.ce)  dout <= dor;
      end 
    end
    else
      assign dout = dor;
  endgenerate

  //RAMs
  always_ff @(posedge(gclk.clk2x)) begin		
    //RAMs
    if (we)	obuf[waddr] <= wdata;
  end
endmodule

//single port output data buffer
module  fpu_fcmp_output_dbuf #(parameter DOREG=1) 
          (input iu_clk_type gclk,
           input  fpu_fcmp_fu_out_type     din,
           input  bit [NTHREADIDMSB:0]	raddr,	//IU read addr
           output fpu_fcmp_out_type		     dout	  //read data (to IU)
            );	
            
  (* syn_ramstyle = "select_ram" *)	fpu_fcmp_out_type	         obuf[0:NTHREAD-1];	//RAM
  fpu_fcmp_out_type	         dor;			//output register

  (* syn_maxfan=8 *) bit [NTHREADIDMSB:0]				waddr;			//TDM write addr
  (* syn_maxfan=8 *) bit						        we;			   //TDM we
  fpu_fcmp_out_type					     wdata;			//TDM data

  assign dor = obuf[raddr];

  assign waddr = din.tid;
  assign we    = din.valid;
  assign wdata = din.data;
  generate
    if (DOREG) begin
     // always_ff @(posedge gclk.clk) begin
      always_ff @(posedge gclk.clk2x) begin
        if (gclk.ce) dout <= dor;
      end 
    end
    else
      assign dout = dor;
  endgenerate

  //RAMs
  always_ff @(posedge(gclk.clk2x)) begin
    if (we)	obuf[waddr] <= wdata;
  end
endmodule

module fpu_if (input iu_clk_type gclk, input rst,
      input   fpu_in_type   fpu_in,
      output  fpu_out_type  fpu_out,
      output  bit           fpop_valid,
      output  bit           fcmp_valid,
      output  bit           new_replay
      );
  
  fpu_fpop_fu_out_type  fpop_dout;      // multiply, add, int <-> float conversion result output
  fpu_fcmp_fu_out_type  cmp_dout;       // comparator result output
  fpu_fpop_out_type     fpop_dbuf_dout;
  
  bit add_valid, mul_valid, cmp_valid, move_valid, itos_valid, itod_valid, stoi_valid, dtoi_valid, op1_zero;
  bit add_valid_2x, mul_valid_2x, cmp_valid_2x, itos_valid_2x, itod_valid_2x, stoi_valid_2x, dtoi_valid_2x;
  bit add_valid_del, mul_valid_del, cmp_valid_del, move_valid_del, itos_valid_del, itod_valid_del, stoi_valid_del, dtoi_valid_del;
  bit sp_result_del, op1_zero_del;  
  bit fpop_result_sp_overflow, fpop_result_sp_underflow;
  bit itos_rdy, itod_rdy, stoi_rdy, stod_rdy, conv_rdy, conv_rdy_del;
  bit [31:0] itos_result, stoi_result, dtoi_result;
  bit [63:0] itod_result;
  bit mul_rdy, add_rdy, add_rdy_del, fpop_rdy;
  bit [63:0] mul_result, add_result, add_result_del, fpop_result, fpop_result_del, conv_result, conv_result_del;
  bit [31:0] fpop_result_sp, move_data, move_result;
  bit [63:0] fpu_op1_conv, fpu_op2_conv, fpu_op1_del, fpu_op2_del, fpu_op1, fpu_op2;
  bit [5:0] addsub_op, addsub_op_del; // control signal for floating point adder/subtracter
  bit stoi_overflow, stoi_invalidop, dtoi_overflow, dtoi_invalidop;
  
  typedef struct {
    bit invalid_op;
    bit overflow;
    bit underflow;
  } fp_muladd_exception_type;
  
  fp_muladd_exception_type add_exc, add_exc_del, mul_exc, fpop_exc, fpop_exc_del, conv_exc, conv_exc_del;
  
  always_comb begin  
      addsub_op = '0;
      move_valid = '0;
      add_valid = '0;
      mul_valid = '0;
      cmp_valid = '0;
      itos_valid = '0;
      itod_valid = '0;
      stoi_valid = '0;
      dtoi_valid = '0;
      op1_zero = '0;
      
      // mux result of a fmov, fneg, or fabs to the fpu output (after 1 cycle)
      fpu_out.fpop_result = fpop_dbuf_dout;
      if (move_valid_del) begin
        fpu_out.fpop_result.result[63:32] = move_result;
        fpu_out.fpop_result.overflow = '0;
        fpu_out.fpop_result.underflow = '0;
        fpu_out.fpop_result.invalid_op = '0;
      end
      
      move_data = fpu_in.op2[63:32];
      
      unique case (fpu_in.fp_op)
        FP_ADD: begin add_valid = ~fpu_in.replay; addsub_op = FP_CTRL_ADD; end
        FP_SUB: begin add_valid = ~fpu_in.replay; addsub_op = FP_CTRL_SUB; end
        FP_MUL: mul_valid = ~fpu_in.replay;
        FP_CMP: cmp_valid = ~fpu_in.replay;
        FP_MOV: move_valid = '1;
        FP_NEG: begin move_data[31] = ~fpu_in.op2[63]; move_valid = '1; end
        FP_ABS: begin move_data[31] = 1'b0; move_valid = '1; end
        FP_ITOS: itos_valid = ~fpu_in.replay;
        FP_ITOD: itod_valid = ~fpu_in.replay;
        FP_STOI: stoi_valid = ~fpu_in.replay;
        FP_DTOI: dtoi_valid = ~fpu_in.replay;
        FP_STOD, FP_DTOS: begin add_valid = ~fpu_in.replay; addsub_op = FP_CTRL_ADD; op1_zero = '1; end
        default:;
      endcase
      mul_valid_2x = mul_valid & gclk.ce;
      cmp_valid_2x = cmp_valid & gclk.ce;
      add_valid_2x = add_valid & gclk.ce;
      itos_valid_2x = itos_valid & gclk.ce;
      itod_valid_2x = itod_valid & gclk.ce;
      stoi_valid_2x = stoi_valid & gclk.ce;
      dtoi_valid_2x = dtoi_valid & gclk.ce;
  end
  
  always_ff @(posedge gclk.clk) begin
      fpop_valid <= fpu_in.replay & ((fpu_in.fp_op == FP_ADD) | (fpu_in.fp_op == FP_STOD) | (fpu_in.fp_op == FP_DTOS) |
                                       (fpu_in.fp_op == FP_MUL) | 
                                       (fpu_in.fp_op == FP_SUB) |
                                       (fpu_in.fp_op == FP_ITOS) |
                                       (fpu_in.fp_op == FP_ITOD) |
                                       (fpu_in.fp_op == FP_STOI) |
                                       (fpu_in.fp_op == FP_DTOI)); // data is always ready on the first replay
      fcmp_valid <= fpu_in.replay & (fpu_in.fp_op == FP_CMP);
      new_replay <= add_valid | mul_valid | cmp_valid | itos_valid | itod_valid | stoi_valid | dtoi_valid;
      move_valid_del <= move_valid;
      move_result <= move_data;
  end
      
  // tracks tid and single precision status of FPOP1 operations except for mov, neg & abs
  sh_reg #(.WIDTH(NTHREADIDMSB+2),
               .DEPTH(FP_CONV_SP_DP_LATENCY+FP_MULT_LATENCY+FP_CONV_DP_SP_LATENCY)) //fp multiply + dp->sp conversion latency
               fp_tid_reg
               (.clk(gclk.clk2x),
                .din({fpu_in.sp_result,fpu_in.tid}),
                .dout({sp_result_del, fpop_dout.tid}));    
  
  // buffers result from adder, multiplier or int/float conversion unit while dp->sp conversion takes place
      
  sh_reg #(.WIDTH(64+4),
               .DEPTH(FP_CONV_DP_SP_LATENCY)) // dp->sp conversion latency
               fpmuladd_result_reg
               (.clk(gclk.clk2x),
                .din({fpop_exc.overflow, fpop_exc.underflow, fpop_exc.invalid_op, fpop_rdy, fpop_result}),
                .dout({fpop_exc_del.overflow, fpop_exc_del.underflow, fpop_exc_del.invalid_op, fpop_dout.valid, fpop_result_del}));    
 
  // buffers adder result to line it up with multiplier result   
  sh_reg #(.WIDTH(64+4),
               .DEPTH(FP_MULT_LATENCY-FP_ADD_LATENCY)) // assumes multiplier latency > adder latency
               fpadd_result_reg
               (.clk(gclk.clk2x),
                .din({add_rdy, add_exc.overflow, add_exc.underflow, add_exc.invalid_op, add_result}),
                .dout({add_rdy_del, add_exc_del.overflow, add_exc_del.underflow, add_exc_del.invalid_op, add_result_del}));

  // buffers int/float conversion result to line it up with multiplier and adder results   
  sh_reg #(.WIDTH(64+4),
               .DEPTH(FP_MULT_LATENCY-FP_CONV_FLOAT_INT_LATENCY))
               conv_result_reg
               (.clk(gclk.clk2x),
                .din({conv_rdy, conv_exc.overflow, conv_exc.underflow, conv_exc.invalid_op, conv_result}),
                .dout({conv_rdy_del, conv_exc_del.overflow, conv_exc_del.underflow, conv_exc_del.invalid_op, conv_result_del})); 
     
  // buffers thread id for compare unit    
  sh_reg #(.WIDTH(NTHREADIDMSB+1),
               .DEPTH(FP_CMP_LATENCY+FP_CONV_SP_DP_LATENCY)) //fp compare + sp->dp conversion latency
               fpcmp_tid_reg
               (.clk(gclk.clk2x),
                .din(fpu_in.tid),
                .dout(cmp_dout.tid));   
 
   // buffers original operands and control signals while sp->dp conversion takes place
   sh_reg #(.WIDTH(143),
           .DEPTH(FP_CONV_SP_DP_LATENCY))
           fp_op_delay_reg
           (.clk(gclk.clk2x),
            .din({add_valid_2x, mul_valid_2x, cmp_valid_2x, itos_valid_2x, itod_valid_2x, stoi_valid_2x, dtoi_valid_2x, fpu_in.sp_ops, addsub_op, op1_zero, fpu_in.op2, fpu_in.op1}),
            .dout({add_valid_del, mul_valid_del, cmp_valid_del, itos_valid_del, itod_valid_del, stoi_valid_del, dtoi_valid_del, sp_ops_del, addsub_op_del, op1_zero_del, fpu_op2_del, fpu_op1_del}));

  always_comb begin
    if (sp_ops_del) begin
        fpu_op1 = fpu_op1_conv;
        fpu_op2 = fpu_op2_conv;
    end
    else begin
        fpu_op1 = fpu_op1_del;
        fpu_op2 = fpu_op2_del;
    end
    
    if(op1_zero_del)
        fpu_op1 = '0;
    
    fpop_result = mul_result;
    fpop_exc = mul_exc;
    if (add_rdy_del) begin
        fpop_result = add_result_del;
        fpop_exc = add_exc_del;
    end
    if (conv_rdy_del) begin
        fpop_result = conv_result_del;
        fpop_exc = conv_exc_del;
    end
    fpop_rdy = mul_rdy | add_rdy_del | conv_rdy_del;
    
    fpop_dout.data.result = fpop_result_del;
    if (sp_result_del) begin
      fpop_dout.data.result[63:32] = fpop_result_sp;
      fpop_dout.data.overflow  = fpop_exc_del.overflow | fpop_result_sp_overflow;
      fpop_dout.data.underflow = fpop_exc_del.underflow | fpop_result_sp_underflow;
    end
    else begin
      fpop_dout.data.overflow  = fpop_exc_del.overflow;
      fpop_dout.data.underflow = fpop_exc_del.underflow;
    end
    fpop_dout.data.invalid_op = fpop_exc_del.invalid_op;
  end    
      
  fp_conv_sp_dp gen_fpu_conv_sp_dp1(.clk(gclk.clk2x),
                     .sclr(rst),
                     .operation_nd(1'b1),
                     .a(fpu_in.op1[63:32]),
                     .rdy(),
                     .result(fpu_op1_conv));              
                      
  fp_conv_sp_dp gen_fpu_conv_sp_dp2(.clk(gclk.clk2x),
                     .sclr(rst),
                     .operation_nd(1'b1),
                     .a(fpu_in.op2[63:32]),
                     .rdy(),
                     .result(fpu_op2_conv));     
      
  fp_addsub_dp  gen_fpu_addsub_dp(.clk(gclk.clk2x),
                    .sclr(rst),
                    .operation_nd(add_valid_del),
                    .operation(addsub_op_del),
                    .a(fpu_op1),
                    .b(fpu_op2),
                    .rdy(add_rdy),
                    .overflow(add_exc.overflow),
                    .underflow(add_exc.underflow),
                    .invalid_op(add_exc.invalid_op),
                    .result(add_result));
                    
  fp_mult_dp   gen_fpu_mult_dp(.clk(gclk.clk2x),
                      .sclr(rst),
                      .operation_nd(mul_valid_del),
                      .a(fpu_op1),
                      .b(fpu_op2),
                      .rdy(mul_rdy),
                      .overflow(mul_exc.overflow),
                      .underflow(mul_exc.underflow),
                      .invalid_op(mul_exc.invalid_op),
                      .result(mul_result));                  
                      
  fp_conv_dp_sp gen_fpu_conv_dp_sp(.clk(gclk.clk2x),
                     .sclr(rst),
                     .operation_nd(1'b1),
                     .a(fpop_result),
                     .rdy(),
                     .overflow(fpop_result_sp_overflow),
                     .underflow(fpop_result_sp_underflow),
                     .result(fpop_result_sp));   
  
  fp_cmp_dp   gen_fpu_cmp_dp(.clk(gclk.clk2x),
                      .sclr(rst),
                      .operation_nd(cmp_valid_del),
                      .a(fpu_op1),
                      .b(fpu_op2),
                      .rdy(cmp_dout.valid),
                      .invalid_op(cmp_dout.data.invalid_op),
                      .result(cmp_dout.data.cc));
                      
  // float <-> int conversion blocks
                      
/*  fp_dtoi      gen_fpu_conv_dtoi (
                      .a(fpu_op2_del), // Bus [63 : 0] 
                      .operation_nd(dtoi_valid_del),
                      .clk(gclk.clk2x),
                      .sclr(rst),
                      .result(dtoi_result), // Bus [31 : 0] 
                      .overflow(dtoi_overflow),
                     	.invalid_op(dtoi_invalidop),
                     	.rdy(dtoi_rdy));  */
                     	
  fp_dtoi      gen_fpu_conv_dtoi (
                      .din(fpu_op2_del), // Bus [63 : 0] 
                      .en(dtoi_valid_del),
                      .clk(gclk.clk2x),
                      .rst(rst),
                      .dout(dtoi_result), // Bus [31 : 0] 
                      .overflow(dtoi_overflow),
                     	.invalid_op(dtoi_invalidop),
                     	.rdy(dtoi_rdy));     	
                   	
  fp_itod      gen_fpu_conv_itod (
                      .a(fpu_op2_del[63:32]), // Bus [31 : 0]
                      .operation_nd(itod_valid_del),
                      .clk(gclk.clk2x),
                      .sclr(rst),
                      .result(itod_result), // Bus [63 : 0]
                     	.rdy(itod_rdy));
                     	
  fp_itos      gen_fpu_conv_itos (
                      .a(fpu_op2_del[63:32]), // Bus [31 : 0]
                      .operation_nd(itos_valid_del),
                      .clk(gclk.clk2x),
                      .sclr(rst),
                      .result(itos_result), // Bus [31 : 0]
                     	.rdy(itos_rdy));
                     	
/*  fp_stoi      gen_fpu_conv_stoi (
                      .a(fpu_op2_del[63:32]), // Bus [31 : 0]
                      .operation_nd(stoi_valid_del),
                      .clk(gclk.clk2x),
                      .sclr(rst),
                      .result(stoi_result), // Bus [31 : 0]
                      .overflow(stoi_overflow),
                     	.invalid_op(stoi_invalidop),
                     	.rdy(stoi_rdy)); */
                     	
   fp_stoi      gen_fpu_conv_stoi (
                      .din(fpu_op2_del[63:32]), // Bus [63 : 0] 
                      .en(stoi_valid_del),
                      .clk(gclk.clk2x),
                      .rst(rst),
                      .dout(stoi_result), // Bus [31 : 0] 
                      .overflow(stoi_overflow),
                     	.invalid_op(stoi_invalidop),
                     	.rdy(stoi_rdy)); 
  
  always_comb
  begin
      conv_result = '0;
      conv_exc.overflow = '0;
      conv_exc.invalid_op = '0;
      conv_exc.underflow = '0;
      if (itod_rdy)
          conv_result = itod_result;
      if (itos_rdy)
          conv_result[63:32] = itos_result;
      if (stoi_rdy) begin
          conv_result[63:32] = stoi_result;
          conv_exc.overflow = stoi_overflow;
          conv_exc.invalid_op = stoi_invalidop;
      end
      if (dtoi_rdy) begin
          conv_result[63:32] = dtoi_result;
          conv_exc.overflow = dtoi_overflow;
          conv_exc.invalid_op = dtoi_invalidop;
      end 
      conv_rdy = itod_rdy | itos_rdy | stoi_rdy | dtoi_rdy;
  end 
                     	                  	 
   fpu_fpop_output_dbuf	fpop_out_buf(.gclk, 
                       .din(fpop_dout),
                       .raddr(fpu_in.tid),	
                       .dout(fpop_dbuf_dout));
                      
   fpu_fcmp_output_dbuf fcmp_out_buf(.gclk,
                        .din(cmp_dout),
                        .raddr(fpu_in.tid),
                        .dout(fpu_out.fcmp_result));
                       
endmodule
  
            
  
  
  