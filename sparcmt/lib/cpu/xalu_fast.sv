//-----------------------------------------------------------------------------
// File:        xalu_fast.v
// Author:      Zhangxi Tan
// Description: complex alu implementation with a fast mul implementation 
//------------------------------------------------------------------------------  
`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libstd::*;
import libiu::*;
import libxalu::*;
`else
`include "libiu.sv"
`include "libxalu.sv"
`endif

//single port div output data buffer
module  xalu_div_output_dbuf 
					(input iu_clk_type gclk,
           input  xalu_fu_out_type     divin,
           input  bit [NTHREADIDMSB:0]	raddr,	//IU read addr
		       output xalu_obuf_type		     dout	  //read data (to IU)
		);	
  (* syn_ramstyle = "select_ram" *)	xalu_obuf_type	         obuf[0:NTHREAD-1];	//RAM
	xalu_obuf_type	         dor;			//output register

  (* syn_maxfan=8 *) bit [NTHREADIDMSB:0]				waddr;			//TDM write addr
  (* syn_maxfan=8 *) bit						        we;			   //TDM we
  xalu_obuf_type					     wdata;			//TDM data

	always_comb begin
	  dout = obuf[raddr];

	  waddr = divin.tid;
	  we    = divin.valid;
	  wdata = divin.data;
  end
    
	//RAMs
	always_ff @(posedge(gclk.clk)) begin			
		//RAMs
		if (we)	obuf[waddr] <= wdata;
	end
endmodule

//TODO: fix autorecover, (need move in_fifo to the second cycle)
module xalu_if_fast (input iu_clk_type gclk, input rst,
	       input 	 xalu_dsp_in_type  	  xalu_in,	   //input from IU
	       output 	alu_dsp_out_type     xalu_out,
	       output 	bit			               new_replay	//new replay bit
	       );	
	
	typedef struct {
		bit [NTHREADIDMSB:0]	          tid;		   //thread id, replicated register
		bit			                         replay;		//replay bit
    bit [$bits(mul_ctrl_type)-1:0] mode;    //mode
		xalu_obuf_type	                xalu_res;
		xalu_valid_type		              res_ready;
		bit                            op2zero; //op2 is zero (for div by zero detection)
		bit                            valid;   //valid input
		bit                            divz;    //divide by zero flag
	}xalu_if_reg_type;		//pipeline register
	
	xalu_if_reg_type		 ifr;
	
	xalu_obuf_type		   obuf_data;
	
	bit                div_en;           //DIV enable 
	bit                div_ififo_re;     //DIV input fifo RE
  
  xalu_valid_in_type div_iu_vin;       //div valid buffer input from IU
  xalu_valid_in_type div_xalu_vin;     //div valid buffer
  
  xalu_valid_type			 div_vout;		       //valid bit output for div
	
  xalu_in_fifo_type  div_din;          //div data input
  y_reg_type         div_yin;          //div y input
  
  xalu_fu_out_type   mul_dout;         //mul result output
  xalu_fu_out_type   div_dout;         //div result output
  
  (* syn_maxfan = 2 *) bit     op2zero;        
  
  alu_dsp_out_type    v_xalu_out;

		
	always_comb begin		
	  //------------------first cycle comb logic--------------
    //default values   
    div_iu_vin.addr = xalu_in.ififo_data.tid;
    div_iu_vin.we   = '0;
    div_iu_vin.data = '{0, 0};

    //valid buffer input    
    div_xalu_vin.we   = div_dout.valid;
    div_xalu_vin.addr = div_dout.tid;
    div_xalu_vin.data = '{1, 1};    
    
//    op2zero = (xalu_in.ififo_data.op2 == 0) ? '1 : '0;    //this should be retimed for performance
    op2zero = xalu_in.op2zero;
    
    if (!xalu_in.replay) begin    //new requets
    		unique case (xalu_in.ififo_data.mode)
		   c_UDIV, c_SDIV : div_iu_vin.we = xalu_in.valid & (~op2zero);
		   default : ;
		  endcase
		end


    //------------second cycle comb logic-----------------
    //no use output
    v_xalu_out.tag_overflow = '0;

    v_xalu_out.flag.C = '0;
    v_xalu_out.divz   = '0;
    v_xalu_out.result = mul_dout.data.res;
    v_xalu_out.y      = mul_dout.data.y;
    v_xalu_out.flag.N = mul_dout.data.N;
    v_xalu_out.flag.Z = mul_dout.data.Z;
    v_xalu_out.flag.V = mul_dout.data.V;        


    v_xalu_out.valid  = ifr.res_ready.valid & ifr.valid;

    new_replay = '0;

    if (ifr.mode == c_UDIV || ifr.mode == c_SDIV) begin
      v_xalu_out.divz = ifr.op2zero;
      
      v_xalu_out.result = ifr.xalu_res.res;
//      v_xalu_out.y      = ifr.xalu_res.y;
      v_xalu_out.flag.N = ifr.xalu_res.N;
      v_xalu_out.flag.Z = ifr.xalu_res.Z;
      v_xalu_out.flag.V = ifr.xalu_res.V;        

      //replay request
      new_replay = (ifr.replay)? !ifr.res_ready.valid : !v_xalu_out.divz;
    end


    if (LUTRAMPROT) begin
    			v_xalu_out.parity_error = ^{ifr.xalu_res.res, ifr.xalu_res.N, ifr.xalu_res.Z, ifr.xalu_res.V, ifr.xalu_res.parity, ifr.res_ready};

       v_xalu_out.parity_error =  v_xalu_out.parity_error & ifr.valid;
			//TODO: add automatic recover from LUTRAM seu. need a new recover bit in thread state. have to wait till the next scheduled thread, because of limited R/W port on input/output FIFOs
		end
		else
		   v_xalu_out.parity_error = '0;	

    //output
    xalu_out = v_xalu_out;
	end

	
	always_ff @(posedge gclk.clk) begin	
		ifr.tid    <= xalu_in.ififo_data.tid;
		ifr.replay <= xalu_in.replay;       //old replay
		ifr.mode   <= xalu_in.ififo_data.mode;		
		ifr.valid  <= xalu_in.valid;        //input is valid
		  
		ifr.op2zero   <= op2zero;
		
		//latch result from xalu
		ifr.xalu_res  <= obuf_data;
		ifr.res_ready <= (xalu_in.ififo_data.mode == c_UDIV || xalu_in.ififo_data.mode == c_SDIV) ? div_vout : '{1, 1};		        //the comparator can be shared 
	end

 
  //IU->DIV input FIFO
  div_in_fifo	div_ififo(.gclk, .rst, 
                           .din(xalu_in.ififo_data),
                           .yin(xalu_in.y),
                           .we(div_iu_vin.we),		
                           .re(div_ififo_re),
                           .dout(div_din),
                           .yout(div_yin),
                           .valid(div_en));		
  

	//XALU->IU result buffer
	xalu_div_output_dbuf	out_buf(.gclk, 
                       .divin(div_dout),
            	          .raddr(xalu_in.ififo_data.tid),	
                       .dout(obuf_data)
   );

 
		      		  
	//valid bit for div
  xalu_valid_buf div_valid_buf(.gclk, .rst,
                               .iu_vin(div_iu_vin),
                               .xalu_vin(div_xalu_vin),
                               .vout(div_vout));
  
  //connect to mul/shf unit
  alu_mul_shf_fast gen_mul_shf(.gclk, .rst,
                          .din(xalu_in.ififo_data),                  
                          .dout(mul_dout));
                          
  alu_div     gen_div(.gclk, .rst,
                      .din(div_din),
                      .en(div_en),
                      .yin(div_yin),
                      .dout(div_dout),
                      .re(div_ififo_re));
endmodule