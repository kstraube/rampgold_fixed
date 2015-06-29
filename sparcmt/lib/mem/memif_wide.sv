//------------------------------------------------------------------------------   
// File:        memif_wide.v
// Author:      Zhangxi Tan
// Description: iu memory interface: mem command queue. wide interface to ddr2 
//              mem controller (256-bit)
//------------------------------------------------------------------------------
`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libmemif::*;
import libiu::*;
import libcache::*;
`else
`include "../cpu/libiu.sv"
`include "../cpu/libmmu.sv"
`include "../cpu/libcache.sv"
`include "libmemif.sv"
`endif

//inst memory command fifo: input register (IU) is in module imem_if 
module imem_cmd_fifo_wide(input iu_clk_type gclk, input rst,
		     input  bit			             we,
		     input  bit			             re,
		     input  imem_cmd_fifo_type	din,
		     output imem_cmd_fifo_type	dout,
		     output bit			             empty,
		     output cache_ram_read_wide_in_type	bram_addr);
	mem_cmd_fifo_pt_type		pt;		      //fifo pointer
	bit [NTHREADIDMSB:0]		addr;		    //TDM fifo addr
	bit							        d_read;		  //just read
	bit							        last_read;	//latest operation is read
	//memory content
  (* syn_ramstyle = "select_ram" *)	imem_cmd_fifo_type	 cmdfifo[0:NTHREAD-1];

	imem_cmd_fifo_type		fifo_out;	//wires


	always_ff @(posedge gclk.clk) begin
		if (rst) d_read <= '0; else d_read <= re;
	end

	always_ff @(negedge gclk.clk) begin
		if (rst)
			last_read <= '1;
		else begin
			if (we)
				last_read <= '0;
			else if (d_read) 
				last_read <= '1;
			else
				last_read <= last_read;
		end
	end

	always_ff @(negedge gclk.clk) begin		//tail pointer written from IU	
		if (rst)
			pt.tail <= '0;
		else begin
			//cross clk domain, complete at ~400 MHz
			pt.tail <= (we) ? pt.tail+1 : pt.tail;
		end
	end 

	always_ff @(posedge gclk.clk) begin		//head pointer read by mem control
		if (rst)
			pt.head <= '0;
		else
			pt.head <= (re) ? pt.head + 1 : pt.head;
	end

	//complete at ~400 MHz
	assign addr = (gclk.ce)? pt.head : pt.tail;	//ram address
	assign empty = (pt.head == pt.tail) ? last_read : '0;
	assign fifo_out = cmdfifo[addr]; 
	
	//RAMs
	always_ff @(negedge gclk.clk) begin		//write at negedge
		//RAMs
		if (we) cmdfifo[addr] <= din;
	end
	
	always_ff @(posedge gclk.clk) begin  //output register
		dout <= fifo_out;
		
		//read out bram addr
		bram_addr.tid     <= fifo_out.tid;
   	bram_addr.index.I <= fifo_out.ret_index;    //only read cache tag		
	end
endmodule

//data memory command fifo : input register (IU) is in module dmem_if
module dmem_cmd_fifo_wide(input iu_clk_type gclk, input rst,
		     input  bit				             we,
		     input  bit				             re,
		     input  dmem_cmd_fifo_type		din,
		     output dmem_cmd_fifo_type		dout,
		     output bit 			empty,
		     output cache_ram_read_wide_in_type	bram_addr);
	mem_cmd_fifo_pt_type		pt;		//fifo pointer
	bit [NTHREADIDMSB:0]		addr;		//TDM fifo addr
	//bit [NTHREADIDMSB:0]		ntail;		//wire: tail+1
	bit							d_read;		//just read
	bit							last_read;	//latest operation is read

	dmem_cmd_fifo_type		fifo_out;
	//memory content
  (* syn_ramstyle = "select_ram" *)	dmem_cmd_fifo_type	cmdfifo[0:NTHREAD-1];
		
	
	always_ff @(posedge gclk.clk) begin
			if (rst) d_read <= '0; else d_read <= re;
	end

	always_ff @(negedge gclk.clk) begin
		if (rst)
			last_read <= '1;
		else begin
			if (we) 
				last_read <= '0;
			else if (d_read) 
				last_read <= '1;
     	else 
				last_read <= last_read;
		end
	end

	always_ff @(negedge gclk.clk) begin		//tail pointer written from IU	
		if (rst)
			pt.tail <= '0;
		else begin
			//cross clk domain, complete at ~400 MHz
			pt.tail <= (we) ? pt.tail+1 : pt.tail;
		end
	end 

	always_ff @(posedge gclk.clk) begin		//head pointer read by mem control
		if (rst)
			pt.head <= '0;
		else
			pt.head <= (re) ? pt.head + 1 : pt.head;
	end

	//complete at ~400 MHz
	assign addr = (gclk.ce)? pt.head : pt.tail;	//ram address
	assign fifo_out = cmdfifo[addr]; 
  assign empty = (pt.head == pt.tail) ? last_read : '0;  //is head = tail
                 	
	//RAMs & cacheram addr
	always_ff @(negedge gclk.clk) begin		//write at negedge
		//RAMs
		if (we) cmdfifo[addr] <= din;		
	end
	
	always_ff @(posedge gclk.clk) begin //output register
		dout <= fifo_out;

    //read out bram addr
		bram_addr.tid     <= fifo_out.tid;
    bram_addr.index.D <= fifo_out.ret_index; 
	end

endmodule

//inst memory if
module imem_if_wide(input iu_clk_type gclk, input rst,
	       //memory<->IU
	       input bit [NTHREADIDMSB:0]	iu2mem_tid,	//request busy bit read back
	       input  mem_cmd_in_type		   iu2mem_cmd,	//memory command
	       output mem_stat_out_type		 mem2iu_stat,	//output busy bit
	       //memory<->cache
	       input  cache_ram_wide_out_type		cacheram2mem,
	       output cache_ram_wide_in_type		 mem2cacheram,
	       //memctrl if <-> mem ctrl
	       input  mem_ctrl_wide_out_type		 from_mem,	//mem->I
	       output mem_ctrl_wide_in_type		  to_mem,
	       //parity or ecc errors
	       output bit			luterr
		);
	
	mem_cmd_in_type		rmem_cmd;			//input register for mem_cmd
	//bit			icmd_fifo_we;			//i-cmd fifo we
	//bit			icmd_fifo_re;			//i-cmd fifo re
	bit			               icmd_fifo_empty;		//i-cmd fifo empty
	imem_cmd_fifo_type	  icmd_fifo_din;			 //i-cmd fifo input
	imem_cmd_fifo_type	  icmd_fifo_dout;			//i-cmd fifo output
	
	mem_stat_buf_in_type	mem_stat_in;			 //status buffer input
	mem_stat_out_type	   mem_stat_out;			//status buffer output

	//mem_ctrl_wide_in_type	    mem_out_reg, mem_out_v;		//mem output register
	mem_ctrl_wide_in_type	    mem_out_v;		    //mem output register

	
	cache_ram_read_wide_in_type	cache_read_addr;		//bram read addr

//	bit			new_req;			//toggle every two cycle, when re = 1
	//credit based flow control
	memif_flow_control_type		xfer_ctrl_v, xfer_ctrl_r; 
	
		
	//-----------------------memory if<-> IU-----------------------
	//always_comb begin
	always_comb begin
		icmd_fifo_din.tid        = rmem_cmd.tid;
		icmd_fifo_din.cmd        = rmem_cmd.cmd.I;
		icmd_fifo_din.ret_index  = rmem_cmd.ret_index.I;
		icmd_fifo_din.parity     = (LUTRAMPROT)? ^{rmem_cmd.tid_parity, rmem_cmd.cmd.I, rmem_cmd.ret_index.I} : '0;  

		mem_stat_in.iu.rtid        = iu2mem_tid;
		mem_stat_in.iu.wtid        = rmem_cmd.tid;				
		mem_stat_in.iu.we          = rmem_cmd.valid;
		mem_stat_in.iu.wdin.busy   = !rst; 	//busy
		mem_stat_in.iu.wdin.parity = (LUTRAMPROT)? !rst : '0;
	end
	
	//-----------------------To memory-----------------------
	//always_comb begin		
  
  //synthesis translate_off
  assert (xfer_ctrl_r.ccnt <= MEMCREDIT) else $display("@%t imem network flow control error", $time);
  //synthesis translate_on
	
	always_comb begin		//flow control
      //default value
      xfer_ctrl_v.ccnt    = xfer_ctrl_r.ccnt;        
      xfer_ctrl_v.fifo_re = '0;
      xfer_ctrl_v.valid   = '0;

      if (!icmd_fifo_empty && (xfer_ctrl_r.ccnt > 0 || from_mem.ctrl.cmd_re == 1'b1)) begin
          xfer_ctrl_v.fifo_re = '1;     //advance the cmd fifo rd counter
          xfer_ctrl_v.valid   = '1;     //data to memctrl is valid
              
          if (!from_mem.ctrl.cmd_re)
               xfer_ctrl_v.ccnt = xfer_ctrl_r.ccnt - 1;      //keep sending as long as we have credit
      end
      else begin          
           if (from_mem.ctrl.cmd_re)
               xfer_ctrl_v.ccnt = xfer_ctrl_r.ccnt + 1;      //return packets
      end
	end

	always_ff @(posedge gclk.clk) begin
		if (rst) begin
			xfer_ctrl_r.ccnt    <= MEMCREDIT;		  //has MAX credit
      xfer_ctrl_r.fifo_re <= '0;
			xfer_ctrl_r.valid   <= '0;
		end
		else 
      xfer_ctrl_r <= xfer_ctrl_v;    
	end
 
  always_comb begin
		//mem 1st half
		mem_out_v.s1.tid              = icmd_fifo_dout.tid;
		mem_out_v.s1.tid_index_parity = (LUTRAMPROT)?icmd_fifo_dout.parity ^ (^icmd_fifo_dout.cmd) : '0;
		mem_out_v.s1.ret_index.I      = icmd_fifo_dout.ret_index;
    mem_out_v.s1.valid            = xfer_ctrl_r.valid; 
		
		//mem 2nd half
	  
		mem_out_v.s2.addr_prefix.I = cacheram2mem.tag.tag.I; 
    mem_out_v.s2.data          = cache_data_wide_none;    //no use for i-cache, because never write back
    
    
		mem2cacheram.read          = cache_read_addr;

		if (icmd_fifo_dout.cmd == ITLB_WRITE) 
			mem_out_v.s1.we = xfer_ctrl_r.valid; 
		else
			mem_out_v.s1.we = '0;
	end

	//-----------------------From memory-----------------------
	always_comb begin
		mem2cacheram.write.tid     = from_mem.res.tid;
		mem2cacheram.write.index.I = from_mem.res.ret_index.I;
		mem2cacheram.write.data    = from_mem.res.data;
		mem2cacheram.write.we_data.I  = {ICSIZE{from_mem.res.valid}};
			
		mem_stat_in.mem.wtid = from_mem.res.tid;
		mem_stat_in.mem.we   = from_mem.res.done;
		mem_stat_in.mem.wdin = '{0, 0};			//memory is ready

		mem2cacheram.write.tag    = cache_tag_none;
		mem2cacheram.write.we_tag = '0;		
	end


/*  assign to_mem = mem_out_reg;


	always @(posedge gclk.clk) begin
		
		rmem_cmd    <= iu2mem_cmd;				//cmd fifo input register
		
		mem2iu_stat <= mem_stat_out;			//stat buffer output register

		mem_out_reg.s1 = mem_out_v.s1;			//output register		
		
	
		if (rst) begin
			mem_out_reg.s1.valid = '0;			
		end
				
		luterr <= (LUTRAMPROT)? ^icmd_fifo_dout : '0;		 
	end
	
	//latch result from cacheram, also help routing
  always_ff @(negedge gclk.clk) begin
     mem_out_reg.s2 <= mem_out_v.s2;    
  end

*/

  function automatic mem_ctrl_in_s1_type get_mem_out_reg_s1();
    //posedge function
`ifndef SYNP94    
    mem_ctrl_in_s1_type s1 = mem_out_v.s1;			//output register		
`else
    mem_ctrl_in_s1_type s1;			//output register		
    s1 = mem_out_v.s1;			//output register		
`endif    
    
    if (rst) s1.valid = '0;			
      
    return s1;
  endfunction
   

	always_ff @(posedge gclk.clk) begin		
		rmem_cmd    <= iu2mem_cmd;				 //cmd fifo input register
		mem2iu_stat <= mem_stat_out;			//stat buffer output register

	  to_mem.s1 <= get_mem_out_reg_s1();	  			

		luterr <= (LUTRAMPROT)? ^icmd_fifo_dout : '0;		 
	end

  //latch result from cacheram, also help routing
  always_ff @(negedge gclk.clk) begin
     to_mem.s2 <= mem_out_v.s2;    
  end

	imem_cmd_fifo_wide	icmd_fifo(.gclk, .rst,
				   .we(rmem_cmd.valid),
		     		.re(xfer_ctrl_r.fifo_re),
		     		.din(icmd_fifo_din),
		     		.dout(icmd_fifo_dout),
		     		.empty(icmd_fifo_empty),
				   .bram_addr(cache_read_addr));

	mem_stat_buf	imem_stat(.gclk, .rst,
				  .statin(mem_stat_in),
				  .statout(mem_stat_out));
endmodule

//data memory if
module dmem_if_wide(input iu_clk_type gclk, input rst,
	       //memory if <->IU
	       input bit [NTHREADIDMSB:0]	iu2mem_tid,	 //request busy bit read back
	       input  mem_cmd_in_type		   iu2mem_cmd,	 //memory command
	       output mem_stat_out_type		 mem2iu_stat,	//output busy bit
	       //memory if <->cache
	       input  cache_ram_wide_out_type		cacheram2mem,
	       output cache_ram_wide_in_type		 mem2cacheram,
	       //memctrl if <-> mem ctrl
	       input  mem_ctrl_wide_out_type		  from_mem,		//mem->d
	       output mem_ctrl_wide_in_type		  to_mem,
	       //parity or ecc errors
	       output bit			luterr
		);
	
	mem_cmd_in_type		  rmem_cmd;			//input register for mem_cmd
	bit			             dcmd_fifo_empty;		//i-cmd fifo empty
	dmem_cmd_fifo_type	dcmd_fifo_din;			 //i-cmd fifo input
	dmem_cmd_fifo_type	dcmd_fifo_dout;			//i-cmd fifo output
	
	mem_stat_buf_in_type	mem_stat_in;			 //status buffer input
	mem_stat_out_type	   mem_stat_out;			//status buffer output
	
	//mem_ctrl_wide_in_type	mem_out_reg, mem_out_v;		//mem output register
	mem_ctrl_wide_in_type	    mem_out_v;		    //mem output register
	
	cache_ram_read_wide_in_type	cache_read_addr;		//bram read addr

	//bit			new_req;			//toggle every two cycle, when re
	
	//credit based flow control
	memif_flow_control_type		xfer_ctrl_v, xfer_ctrl_r; 
	
   
	//-----------------------memory <-> IU-----------------------
	//always_comb begin
	always_comb begin
		dcmd_fifo_din.tid        = rmem_cmd.tid;
		dcmd_fifo_din.cmd        = rmem_cmd.cmd.D;
		dcmd_fifo_din.ret_index  = rmem_cmd.ret_index.D;
		dcmd_fifo_din.parity     = (LUTRAMPROT)? ^{rmem_cmd.tid_parity, rmem_cmd.cmd.D, rmem_cmd.ret_index.D} : '0;  

		mem_stat_in.iu.rtid      = iu2mem_tid;
		mem_stat_in.iu.wtid      = rmem_cmd.tid;				
		mem_stat_in.iu.we        = rmem_cmd.valid;
		mem_stat_in.iu.wdin.busy = !rst; 	//busy
		mem_stat_in.iu.wdin.parity = (LUTRAMPROT)? !rst : '0;
	end
	
	//-----------------------To memory-----------------------
  //synthesis translate_off
  assert (xfer_ctrl_r.ccnt <= MEMCREDIT) else $display("@%t dmem network flow control error", $time);
  //synthesis translate_on
  
  always_comb begin		//flow control
      //default value
      xfer_ctrl_v.ccnt    = xfer_ctrl_r.ccnt;        
      xfer_ctrl_v.fifo_re = '0;
      xfer_ctrl_v.valid   = '0;

      if (!icmd_fifo_empty && (xfer_ctrl_r.ccnt > 0 || from_mem.ctrl.cmd_re == 1'b1)) begin
          xfer_ctrl_v.fifo_re = '1;     //advance the cmd fifo rd counter
          xfer_ctrl_v.valid   = '1;     //data to memctrl is valid
              
          if (!from_mem.ctrl.cmd_re)
               xfer_ctrl_v.ccnt = xfer_ctrl_r.ccnt - 1;      //keep sending as long as we have credit
      end
      else begin          
           if (from_mem.ctrl.cmd_re)
               xfer_ctrl_v.ccnt = xfer_ctrl_r.ccnt + 1;      //return packets
      end
  end

  always_ff @(posedge gclk.clk) begin
	  if (rst) begin
		  xfer_ctrl_r.ccnt    <= MEMCREDIT;		  //initialize to max credit
      xfer_ctrl_r.fifo_re <= '0;
		  xfer_ctrl_r.valid   <= '0;
	  end
	  else 
      xfer_ctrl_r <= xfer_ctrl_v;    
  end

	always_comb begin		
		mem_out_v.s1.tid               = dcmd_fifo_dout.tid;
		mem_out_v.s1.tid_index_parity  = (LUTRAMPROT)? dcmd_fifo_dout.parity ^ (^dcmd_fifo_dout.cmd) : '0;
		mem_out_v.s1.ret_index.D       = dcmd_fifo_dout.ret_index;
    mem_out_v.s1.valid             = xfer_ctrl_r.valid; 

		mem_out_v.s2.addr_prefix.D     = cacheram2mem.tag.tag.D; 
		mem_out_v.s2.data              = cacheram2mem.data;		


		mem2cacheram.read = cache_read_addr;

		if (dcmd_fifo_dout.cmd == DCACHE_WB || dcmd_fifo_dout.cmd == DTLB_WRITE) 
			mem_out_v.s1.we = xfer_ctrl_r.valid; 
		else
			mem_out_v.s1.we = '0;
	end

	//-----------------------From memory-----------------------
	always_comb begin
		mem2cacheram.write.tid        = from_mem.res.tid;
		mem2cacheram.write.index.D    = from_mem.res.ret_index.D;
		mem2cacheram.write.data       = from_mem.res.data;
		mem2cacheram.write.we_data.D  = {DCSIZE{from_mem.res.valid}};

	
		mem_stat_in.mem.wtid = from_mem.res.tid;
		mem_stat_in.mem.we   = from_mem.res.done;
		mem_stat_in.mem.wdin = '{0, 0};			//memory is ready

		mem2cacheram.write.tag    = cache_tag_none;
		mem2cacheram.write.we_tag = '0;		
	end

/*	assign to_mem = mem_out_reg;


	always@(posedge gclk.clk) begin
		rmem_cmd <= iu2mem_cmd;				//cmd fifo input register
		
		mem2iu_stat <= mem_stat_out;			//stat buffer output register
		
		mem_out_reg.s1 = mem_out_v.s1;			//output register		
		
		if (rst) begin
			mem_out_reg.s1.valid = '0;			
		end
				
		luterr <= (LUTRAMPROT)? ^dcmd_fifo_dout : '0;		 
	end
	
	//latch result from cacheram, also help routing
  always_ff @(negedge gclk.clk) begin
        mem_out_reg.s2 <= mem_out_v.s2;    
  end

*/
  function automatic mem_ctrl_in_s1_type get_mem_out_reg_s1();
    //posedge function
  `ifndef SYNP94
    mem_ctrl_in_s1_type s1 = mem_out_v.s1;			//output register		
  `else
      mem_ctrl_in_s1_type s1;				//output register		
      s1 = mem_out_v.s1;			//output register		
  `endif    
  
    if (rst) s1.valid = '0;			
      
    return s1;
  endfunction

	always_ff @(posedge gclk.clk) begin
		rmem_cmd    <= iu2mem_cmd;				  //cmd fifo input register
    mem2iu_stat <= mem_stat_out;			 //stat buffer output register
		to_mem.s1   <= get_mem_out_reg_s1();       			 //output register		
		
   	luterr <= (LUTRAMPROT)? ^dcmd_fifo_dout : '0;		 
	end

	//latch result from cacheram, also help routing
  always_ff @(negedge gclk.clk) begin
        to_mem.s2 <= mem_out_v.s2;    
  end

  
	dmem_cmd_fifo_wide	dcmd_fifo(.gclk, .rst,
				.we(rmem_cmd.valid),
		    .re(xfer_ctrl_r.fifo_re),
		    .din(dcmd_fifo_din),
		    .dout(dcmd_fifo_dout),
		    .empty(dcmd_fifo_empty),
				.bram_addr(cache_read_addr));

	mem_stat_buf	dmem_stat(.gclk, .rst,
				  .statin(mem_stat_in),
				  .statout(mem_stat_out));
endmodule
