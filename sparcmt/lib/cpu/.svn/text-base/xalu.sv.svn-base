//---------------------------------------------------------------------------   
// File:        xalu.v
// Author:      Zhangxi Tan
// Description: complex alu implementation, e.g. mul, div, shf, rdy/wry 
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

//use expensive dual port memory here for performance, since read/write might happen at the same time   
module mul_in_fifo(input iu_clk_type gclk, input rst,
		    input  xalu_in_fifo_type	din,
		    input  bit			            we,		  //WE
		    input  bit			            re,		  //RE
		    output xalu_in_fifo_type	dout, 
		    output bit               valid);//output is empty
	(* syn_preserve=1, syn_maxfan=8 *) xalu_fifo_pt_type			pt;		//FIFO pointer
	
//	bit					ce;		//CE
	//memory content
	(* syn_ramstyle = "select_ram" *) xalu_in_fifo_type	     infifo[0:NTHREAD-1];
  bit							           last_read;	          //latest operation is read
	
	assign dout = infifo[pt.head];		

  always_ff @(posedge gclk.clk2x) begin
    if (rst)
      last_read <= '1;
    else begin
      unique case({we & gclk.ce, re})
      2'b00 : last_read <= last_read;
      2'b01 : last_read <= 1'b1;
      2'b10 : last_read <= 1'b0;
      2'b11 : last_read <= 1'b1;
      endcase
    end
  end

	always_ff @(posedge(gclk.clk)) begin	//tail pointer (written from IU) in the 1st half
		if (rst)
		 	pt.tail <= '0;
		else begin
			//cross clk domain, complete at ~400 MHz
			pt.tail <= (we == 1'b1) ? pt.tail + 1 : pt.tail;	
		end 
	end 

	always_ff @(posedge(gclk.clk2x)) begin	//head pointer (read from xalu)		 
		if (rst)
			pt.head <= '0;
		else
			pt.head <= (re) ? pt.head + 1 : pt.head;
	end
	
	//complete at ~400 MHz
	assign valid = (pt.head == pt.tail)? ~last_read : '1;
	
	//RAMs
//	always_ff @(negedge(gclk.clk)) begin		//write at negedge
	always_ff @(posedge gclk.clk2x) begin
		//RAMs
		if (we & ~gclk.ce)	infifo[pt.tail] <= din;
	end
endmodule

//input fifo for clk2x
module div_in_fifo_2x(input iu_clk_type gclk, input rst,
        input  xalu_in_fifo_type	din,
        input  y_reg_type        yin,
        input  bit			            we,		  //WE
        input  bit			            re,		  //RE
        output xalu_in_fifo_type	dout, 
        output y_reg_type        yout,
        output bit               valid);//output is valid	
  xalu_fifo_pt_type			pt;		//FIFO pointer
  
//	bit					ce;		//CE
  //memory content
  (* syn_ramstyle = "select_ram" *) xalu_in_fifo_type	     infifo[0:NTHREAD-1];
  (* syn_ramstyle = "select_ram" *) y_reg_type	            yfifo[0:NTHREAD-1];
  
  bit							           last_read;	          //latest operation is read
  
  assign dout = infifo[pt.head];
  assign yout = yfifo[pt.head];		

  always_ff @(posedge gclk.clk2x) begin
    if (rst)
      last_read <= '1;
    else begin
      unique case({we & gclk.ce, re})
      2'b00 : last_read <= last_read;
      2'b01 : last_read <= 1'b1;
      2'b10 : last_read <= 1'b0;
      2'b11 : last_read <= 1'b1;
      endcase
    end
  end

  always_ff @(posedge(gclk.clk)) begin	//tail pointer (written from IU) in the 1st half
    if (rst)
       pt.tail <= '0;
    else begin
      //cross clk domain, complete at ~400 MHz
      pt.tail <= (we == 1'b1) ? pt.tail + 1 : pt.tail;	
    end 
  end 

  always_ff @(posedge(gclk.clk2x)) begin	//head pointer (read from xalu)		 
    if (rst)
      pt.head <= '0;
    else
      pt.head <= (re) ? pt.head + 1 : pt.head;
  end
  
  //complete at ~400 MHz
  assign valid = (pt.head == pt.tail)? !last_read : '1;
  
  //RAMs
  always_ff @(negedge(gclk.clk)) begin		//write at negedge
    //RAMs
    if (we)	begin 
      infifo[pt.tail] <= din;
      yfifo[pt.tail]  <= yin;
    end      
  end
endmodule

//input fifo for clk 1x
module div_in_fifo(input iu_clk_type gclk, input rst,
        input  xalu_in_fifo_type	din,
        input  y_reg_type        yin,
        input  bit			            we,		  //WE
        input  bit			            re,		  //RE
        output xalu_in_fifo_type	dout, 
        output y_reg_type        yout,
        output bit               valid); //output is valid	
  (* syn_maxfan=8, syn_preserve=1 *) xalu_fifo_pt_type			pt, pt1;		//FIFO pointer
  
  (* syn_srlstyle="registers", syn_preserve=1, syn_maxfan=8 *) bit             ce1, ce2;
  //memory content
  (* syn_ramstyle = "select_ram" *) xalu_in_fifo_type	     infifo[0:NTHREAD-1];
  (* syn_ramstyle = "select_ram" *) y_reg_type	            yfifo[0:NTHREAD-1];
  
  //wires for the stupid synplify memory compiler
  y_reg_type			           w_yout;
  xalu_in_fifo_type	      w_dout;
  
  bit							            last_read;	          //latest operation is read
  bit                     valid_tmp;
  
  (* syn_maxfan=8 *) bit [NTHREADIDMSB:0]		  addr1, addr2;		    //TDM fifo addr
  (* syn_maxfan=8 *) wire						  we_l;			//limit fanout
  
  assign we_l = we;
  
  //manually pipeline the gclk.ce signal
  always_ff @(posedge gclk.clk2x) begin
	ce1 <= gclk.ce;
	ce2 <= ce1;
  end
    
  always_ff @(negedge gclk.clk) begin
    if (rst)
      last_read <= '1;
    else begin
    if (we_l)
      last_read <= '0;
    else if (re)              //no need to use latch re on posedge, because it will be valid for 1 clk cycle 
      last_read <= '1;
    else
      last_read <= last_read;
    end
  end

  always_ff @(negedge(gclk.clk)) begin	//tail pointer (written from IU) at negedge of clk
    if (rst) begin
       pt.tail <= '0;
       pt1.tail <= '0;
    end
    else begin
      //cross clk domain, complete at ~400 MHz
      pt.tail <= (we_l == 1'b1) ? pt.tail + 1 : pt.tail;	
      pt1.tail <= (we_l == 1'b1) ? pt1.tail + 1 : pt1.tail;
    end 
  end 

  always_ff @(posedge(gclk.clk)) begin	//head pointer (read from xalu) at posedge of clk		 
    if (rst) begin
      pt.head <= '0;
      pt1.head <= '0;
    end
    else begin
      pt.head <= (re) ? pt.head + 1 : pt.head;
      pt1.head <=(re) ? pt1.head + 1 : pt1.head;
    end
  end
  
  //complete at ~400 MHz
  assign valid_tmp = (pt.head == pt.tail)? ~last_read : '1;
  always_comb begin 
  	addr1 = (ce2)? pt.head : pt.tail;	//ram address
	addr2 = (ce2)? pt1.head : pt1.tail;	
  end

  //asynchronous read
  assign w_yout = yfifo[addr1];
  assign w_dout = infifo[addr2];
  
  //output register
//  always_ff @(posedge gclk.clk) begin
//     dout  <= infifo[addr];
//     yout  <= yfifo[addr];		
//   end
   always_ff @(posedge gclk.clk2x) begin	
	 if (ce2) begin
	     dout  <= w_dout;
    	 yout  <= w_yout;		
     end
   end
   
  always_ff @(posedge gclk.clk) begin
     valid <= valid_tmp;            //doesn't matter if DIV takes multiple cycles
  end

  //RAMs
  //always_ff @(negedge(gclk.clk)) begin		//write at negedge
  always_ff @(posedge gclk.clk2x) begin
    //RAMs
    if (we_l & ~ce2)	begin 						//we is a high fanout signal
      infifo[addr2] <= din;
      yfifo[addr1]  <= yin;
    end      
  end
endmodule


//dual port output data buffer (2 writes @ clk2x, 1 read)
//module  xalu_output_dbuf #(parameter int DOREG=1) 
module  xalu_output_dbuf #(parameter DOREG=1) 
					(input iu_clk_type gclk,
                     input  xalu_fu_out_type     mulin,
                     input  xalu_fu_out_type     divin,
                     input  bit [NTHREADIDMSB:0]	raddr,	//IU read addr
		            			  output xalu_obuf_type		     dout	  //read data (to IU)
		);	
  (* syn_ramstyle = "select_ram" *)	xalu_obuf_type	         obuf[0:NTHREAD-1];	//RAM
	xalu_obuf_type	         dor;			//output register

  (* syn_maxfan=8 *) bit [NTHREADIDMSB:0]				waddr;			//TDM write addr
  (* syn_maxfan=8 *) bit						        we;			   //TDM we
  xalu_obuf_type					     wdata;			//TDM data

	assign dor = obuf[raddr];

	assign waddr = (gclk.ce)? mulin.tid   : divin.tid;
	assign we    = (gclk.ce)? mulin.valid : divin.valid;
	assign wdata = (gclk.ce)? mulin.data  : divin.data;
	generate
		if (DOREG) begin
//			always_ff @(negedge gclk.clk) begin
			always_ff @(posedge gclk.clk2x) begin
				if (!gclk.ce) dout <= dor;
			end 
		end
		else
			assign dout = dor;
	endgenerate

	//RAMs
	always_ff @(posedge(gclk.clk2x)) begin			//write at posedge of clk2x, time multiplexed by mul and div
		//RAMs
		if (we)	obuf[waddr] <= wdata;
	end
endmodule

//result valid bit buffers for mul/div (1 writes @ clk2x, 1 read/write @ clk2x)
//module xalu_valid_buf #(parameter int DOREG=1) 
module xalu_valid_buf #(parameter DOREG=1) 
(input iu_clk_type gclk, input rst,
		      input  xalu_valid_in_type		 iu_vin,
		      input  xalu_valid_in_type   xalu_vin,
		      output xalu_valid_type	     vout
          );
	bit [NTHREADIDMSB:0]					addr;			//TDM addr
	bit							           we;			  //TDM we
	xalu_valid_type						    wdata;		//TDM data
  (* syn_ramstyle = "select_ram" *)	xalu_valid_type	         valid_buf[0:NTHREAD-1];	//RAM
	xalu_valid_type						    d_iu_valid_out;		       //do reg

	assign addr  = (!gclk.ce | rst) ? iu_vin.addr : xalu_vin.addr;
	assign we    = (!gclk.ce) ? iu_vin.we | rst   : xalu_vin.we;
	assign wdata = (!gclk.ce | rst) ? iu_vin.data : xalu_vin.data;

	assign d_iu_valid_out = valid_buf[addr];

	generate
		if (DOREG) begin
//			always_ff @(negedge gclk.clk) begin
			always_ff @(posedge gclk.clk2x) begin
			 if (!gclk.ce)	vout <= d_iu_valid_out;
			end
		end
		else
			assign vout = d_iu_valid_out;
	endgenerate

	always_ff @(posedge gclk.clk2x) begin
		if (we) valid_buf[addr] <= wdata;
	end  
endmodule


//TODO: 1) add DIV implementation or does nothing here (change Y register to single port, if handle DIV with trap/microcode) 2) fix autorecover, (need move in_fifo to second cycle)
module xalu_if (input iu_clk_type gclk, input rst,
	       input 	 xalu_dsp_in_type  	  xalu_in,	   //input from IU
	       output 	alu_dsp_out_type     xalu_out,
	       output 	bit			               new_replay	//new replay bit
	       );	
	
	typedef struct {
		bit [NTHREADIDMSB:0]	tid;		   //thread id, replicated register
		bit			               replay;		//replay bit
//		mul_ctrl_type		      mode;				//mode		
//  bit [2:0]            mode;    //mode
    bit [$bits(mul_ctrl_type)-1:0] mode; //mode
		xalu_obuf_type	      xalu_res;
		xalu_valid_type		    res_ready;
		bit                  op2zero; //op2 is zero (for div by zero detection)
		bit                  valid;   //valid input
		bit                  divz;    //divide by zero flag
	}xalu_if_reg_type;		//pipeline register
	
	xalu_if_reg_type		 ifr;
	
	xalu_obuf_type		   obuf_data;
	
	bit				           mul_en;		         //MUL enable
	bit                div_en;           //DIV enable 
	(* syn_maxfan=8 *) bit                mul_ififo_re;     //MUL input fifo RE
	bit                div_ififo_re;     //DIV input fifo RE

  xalu_valid_in_type mul_iu_vin;       //mul valid buffer input from IU
  xalu_valid_in_type mul_xalu_vin;     //mul valid buffer input from xalu
  
  xalu_valid_in_type div_iu_vin;       //div valid buffer input from IU
  xalu_valid_in_type div_xalu_vin;     //div valid buffer
  
  xalu_valid_type    mul_vout;         //valid bit output for mul
  xalu_valid_type			 div_vout;		       //valid bit output for div
	
  xalu_in_fifo_type  mul_din;          //mul data input
  xalu_in_fifo_type  div_din;          //div data input
  y_reg_type         div_yin;          //div y input
  
  xalu_fu_out_type   mul_dout;         //mul result output
  xalu_fu_out_type   div_dout;         //div result output
  
  (* syn_maxfan = 2 *) bit     op2zero;        
  
  alu_dsp_out_type    v_xalu_out;

		
	always_comb begin		//first cycle comb logic
    //default values   
    mul_iu_vin.addr = xalu_in.ififo_data.tid;
    mul_iu_vin.we   = '0;
    mul_iu_vin.data = '{0,0};

    div_iu_vin.addr = xalu_in.ififo_data.tid;
    div_iu_vin.we   = '0;
    div_iu_vin.data = '{0, 0};

    //valid buffer input
    mul_xalu_vin.we   = mul_dout.valid;
    mul_xalu_vin.addr = mul_dout.tid;
    mul_xalu_vin.data = '{1, 1};            //always write 1
    
    div_xalu_vin.we   = div_dout.valid;
    div_xalu_vin.addr = div_dout.tid;
    div_xalu_vin.data = '{1, 1};    
    
//    op2zero = (xalu_in.ififo_data.op2 == 0) ? '1 : '0;    //this should be retimed for performance
    op2zero = xalu_in.op2zero;
    
    if (!xalu_in.replay) begin    //new requets
    		unique case (xalu_in.ififo_data.mode)
    		 c_UMUL, c_SMUL,c_SRL, c_SLL, c_SRA : mul_iu_vin.we =  xalu_in.valid;
		   c_UDIV, c_SDIV : div_iu_vin.we = xalu_in.valid & (~op2zero);
		   default : ;
		  endcase
		end
	end

	always_comb begin		//second cycle comb logic
    //no use output
    v_xalu_out.tag_overflow = '0;

		v_xalu_out.result = ifr.xalu_res.res;
		v_xalu_out.y      = ifr.xalu_res.y;
		v_xalu_out.flag.N = ifr.xalu_res.N;
		v_xalu_out.flag.Z = ifr.xalu_res.Z;
		v_xalu_out.flag.V = ifr.xalu_res.V;
		v_xalu_out.flag.C = '0;
		v_xalu_out.divz   = (ifr.mode == c_UDIV || ifr.mode == c_SDIV) ? ifr.op2zero : '0;
		v_xalu_out.valid  = ifr.res_ready.valid & ifr.valid;

    //replay request
		new_replay = (ifr.replay)? !ifr.res_ready.valid : !v_xalu_out.divz;


    if (LUTRAMPROT) begin
    			v_xalu_out.parity_error = ^{ifr.xalu_res.res, ifr.xalu_res.N, ifr.xalu_res.Z, ifr.xalu_res.V, ifr.xalu_res.parity, ifr.res_ready};
       if (ifr.mode == c_UMUL || ifr.mode == c_SMUL)
            v_xalu_out.parity_error = ^{ifr.xalu_res.y} ^ v_xalu_out.parity_error;

       v_xalu_out.parity_error =  v_xalu_out.parity_error & ifr.valid;
			//TODO: add automatic recover from LUTRAM seu. need a new recover bit in thread state. have to wait till the next scheduled thread, because of limited R/W port on input/output FIFOs
		end
		else
		   v_xalu_out.parity_error = '0;	
	end
	
	assign xalu_out = v_xalu_out;
	
	always_ff @(posedge gclk.clk) begin	
		ifr.tid    <= xalu_in.ififo_data.tid;
		ifr.replay <= xalu_in.replay;       //old replay
		ifr.mode   <= xalu_in.ififo_data.mode;		
		ifr.valid  <= xalu_in.valid;        //input is valid
		  
		ifr.op2zero   <= op2zero;
		
		//latch result from xalu
		ifr.xalu_res  <= obuf_data;
		ifr.res_ready <= (xalu_in.ififo_data.mode == c_UDIV || xalu_in.ififo_data.mode == c_SDIV) ? div_vout : mul_vout;		        //the comparator can be shared 
	end


	//IU->MUL input FIFO
	mul_in_fifo	mul_ififo(.gclk, .rst, 
                           .din(xalu_in.ififo_data), 
                           .we(mul_iu_vin.we),		
                           .re(mul_ififo_re),
                           .dout(mul_din),
                           .valid(mul_en));		
  
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
	xalu_output_dbuf	out_buf(.gclk, 
                       .mulin(mul_dout),
                       .divin(div_dout),
            	          .raddr(xalu_in.ififo_data.tid),	
                       .dout(obuf_data)
   );

 

	//valid bit for mul/shf
	xalu_valid_buf	mul_valid_buf(.gclk, .rst,
                           .iu_vin(mul_iu_vin),
                           .xalu_vin(mul_xalu_vin),
                           .vout(mul_vout));
		      		  
	//valid bit for div
  xalu_valid_buf div_valid_buf(.gclk, .rst,
                               .iu_vin(div_iu_vin),
                               .xalu_vin(div_xalu_vin),
                               .vout(div_vout));

  
  //connect to mul/shf unit
  alu_mul_shf gen_mul_shf(.gclk, .rst,
                          .din(mul_din),
                          .en(mul_en),
                          .dout(mul_dout),
                          .re(mul_ififo_re))	/*synthesis syn_maxfan=8*/;
                          
  alu_div     gen_div(.gclk, .rst,
                      .din(div_din),
                      .en(div_en),
                      .yin(div_yin),
                      .dout(div_dout),
                      .re(div_ififo_re));
endmodule