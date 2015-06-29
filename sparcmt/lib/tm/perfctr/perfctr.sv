//------------------------------------------------------------------------------ 
// File:        perfctr.sv
// Author:      Zhangxi Tan
// Description: Performance counter with a ring interface
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps


`ifndef SYNP94
import libconf::*;
import libiu::*;
import libdebug::*;
import libtm::*;
import libio::*;
import libopcodes::*;
import libstd::*;
import libperfctr::*;
`else
`include "../../cpu/libiu.sv"
`include "../libtm.sv"
`include "../../io/libio.sv"
`include "libperfctr.sv"
`endif

//ram based performance counter
(* syn_maxfan=16 *) module perfctr_ram #(parameter bit [PERFCTRADDRMSB:0] IOADDR=0)
               (input iu_clk_type gclk, input bit rst, 
               input  perfctr_ring_ctrl_type ring_ctrl_in,
               input  perfctr_ring_data_type ring_data_in,
               output perfctr_ring_ctrl_type ring_ctrl_out,
               output perfctr_ring_data_type ring_data_out,
               input bit [NTHREADIDMSB:0] increment_addr, input bit increment_en);
  
  (* syn_preserve=1, syn_maxfan=16 *) bit [NTHREADIDMSB:0]  r_inc_addr;
  (* syn_maxfan=16 *)  bit [NTHREADIDMSB:0]  raddr;
  bit [63:0] inc_read_data,inc_write_data;
  (* syn_preserve=1 *) bit r_inc_en;

  (* syn_srlstyle="registers", syn_preserve=1, syn_maxfan=16 *) bit 		 ce1, ce2;               //pipeline ce
  bit [63:0] mem_data;
  
  (* syn_ramstyle = "select_ram" *) reg [63:0] myram[NTHREAD-1:0];
  
  //input registers
  perfctr_ring_data_type r_ring_din[0:1];
  perfctr_ring_ctrl_type r_ring_ctrl_in[0:1];
  
  bit [63:0]  read_data;            //latched data
  bit [31:0]  ring_dout[0:1];       //data out on ring
  
  always_ff @(posedge gclk.clk)
  begin
    r_inc_addr <= increment_addr;
    r_inc_en   <= increment_en;
  end
  
  always_ff @(posedge gclk.clk2x) begin
    ce1 <= gclk.ce;
    ce2 <= ce1;
  end
  
   always_ff @(posedge gclk.clk2x) begin
        //input registers
        r_ring_din[0] <= ring_data_in;
        r_ring_din[1] <= r_ring_din[0];
      
        //ring mux  
        ring_dout[0] <= (IOADDR == r_ring_ctrl_in[0].addr) ? ((ce2)? read_data[63:32] : read_data[31:0]) : r_ring_din[1];
        ring_dout[1] <= ring_dout[0];
  end
  
  always_comb  begin
    //ram controls
    inc_write_data = inc_read_data+1;                     //MCP from inc_read_data to inc_write_data
    raddr = (ce2) ? ring_ctrl_in.tid : increment_addr;
  end
  
  //ring output
  assign ring_data_out = ring_dout[1];
  assign ring_ctrl_out = r_ring_ctrl_in[1];

  always_ff @(posedge gclk.clk) begin
    r_ring_ctrl_in[0] <= ring_ctrl_in;
    r_ring_ctrl_in[1] <= r_ring_ctrl_in[0];
  end
  
  //read port
  assign  mem_data = myram[raddr];
  always_ff @(posedge gclk.clk)	 read_data <= mem_data;
  	
  //write port
  always_ff @(negedge gclk.clk)  inc_read_data <= mem_data;
  	  	
  always_ff @(negedge gclk.clk)  begin
      if(r_inc_en)
        myram[r_inc_addr] <= inc_write_data;          
  end

endmodule

//register based performance counter
module perfctr_reg #(parameter bit [PERFCTRADDRMSB:0] IOADDR=0)
               (input iu_clk_type gclk, input bit rst, 
               input  perfctr_ring_ctrl_type ring_ctrl_in,
               input  perfctr_ring_data_type ring_data_in,
               output perfctr_ring_ctrl_type ring_ctrl_out,
               output perfctr_ring_data_type ring_data_out,
               input bit increment_en);
  
   
  //input registers
  perfctr_ring_data_type r_ring_din[0:1];
  perfctr_ring_ctrl_type r_ring_ctrl_in[0:1];
  
  bit [63:0]  counter;             
  
  bit [31:0]  ring_dout[0:1];        //data out on ring
  
    
  always_ff @(posedge gclk.clk2x) begin
        //input registers
        r_ring_din[0] <= ring_data_in;
        r_ring_din[1] <= r_ring_din[0];
      
        //ring mux  
        ring_dout[0] <= (IOADDR == r_ring_ctrl_in[0].addr) ? ((gclk.ce)? counter[63:32] : counter[31:0]) : r_ring_din[1];
        ring_dout[1] <= ring_dout[0];
  end
  
  
  //ring output
  assign  ring_data_out = ring_dout[1];
  assign  ring_ctrl_out = r_ring_ctrl_in[1];
  
  always_ff @(posedge gclk.clk) begin
    //counter
    if (rst) 
      counter <= '0; 
    else
      counter <= (increment_en) ? counter + 1 : counter;
      
    r_ring_ctrl_in[0] <= ring_ctrl_in;
    r_ring_ctrl_in[1] <= r_ring_ctrl_in[0];
  end
endmodule


//performance counter with ring interface only
module perfctr_if #(parameter bit [PERFCTRADDRMSB:0] IOADDR=0)
               (input iu_clk_type gclk, input bit rst, 
               input  perfctr_ring_ctrl_type ring_ctrl_in,
               input  perfctr_ring_data_type ring_data_in,
               output perfctr_ring_ctrl_type ring_ctrl_out,
               output perfctr_ring_data_type ring_data_out,
               input bit [63:0] counter);     
  //input registers
  perfctr_ring_data_type r_ring_din[0:1];
  perfctr_ring_ctrl_type r_ring_ctrl_in[0:1];
  
  
  bit [31:0]  ring_dout[0:1];        //data out on ring
  
    
  always_ff @(posedge gclk.clk2x) begin
        //input registers
        r_ring_din[0] <= ring_data_in;
        r_ring_din[1] <= r_ring_din[0];
      
        //ring mux  
        ring_dout[0] <= (IOADDR == r_ring_ctrl_in[0].addr) ? ((gclk.ce)? counter[63:32] : counter[31:0]) : r_ring_din[1];
        ring_dout[1] <= ring_dout[0];
  end
  
  
  //ring output
  assign  ring_data_out = ring_dout[1];
  assign  ring_ctrl_out = r_ring_ctrl_in[1];
  
  always_ff @(posedge gclk.clk) begin      
    r_ring_ctrl_in[0] <= ring_ctrl_in;
    r_ring_ctrl_in[1] <= r_ring_ctrl_in[0];
  end
endmodule
  
module perfctr_output_buf (input iu_clk_type gclk, input bit rst, 
			   //input from ring
               input  perfctr_ring_ctrl_type ring_ctrl_in,
               input  perfctr_ring_data_type ring_data_in,
			   //input from IO bus
			   input  bit [NTHREADIDMSB:0]	io_tid,
			   input  bit					io_we,
			   output perfctr_ring_buf_type read_data
               );
   //input registers
   perfctr_ring_data_type r_ring_din;
   perfctr_ring_ctrl_type r_ring_ctrl_in;

   bit [63:0]	write_data;
  
   (* syn_maxfan=16 *) bit [NTHREADIDMSB:0]	addr;		//TDM address
   (* syn_maxfan=16 *) bit 					we;			//TDM we
   perfctr_ring_buf_type					outbuf_din;	

  (* syn_ramstyle = "select_ram" *) perfctr_ring_buf_type outbuf[NTHREAD-1:0];
  
  (* syn_srlstyle="registers", syn_preserve=1, syn_maxfan=16 *) bit 		 ce1, ce2;               //pipeline ce

   bit [NTHREADIDMSB:0]  r_io_tid;
   bit 				   r_io_we;
   
   always_ff @(posedge gclk.clk2x) begin
    ce1 <= gclk.ce;
    ce2 <= ce1;
   end

   //input registers
   always_ff @(posedge gclk.clk) begin
    r_io_tid <= io_tid;
    r_io_we  <= io_we;
   end
   
   always_comb begin
	we   = (ce2)? r_ring_ctrl_in.valid : r_io_we;
	addr = (ce2)? r_ring_ctrl_in.tid : r_io_tid;

	outbuf_din.valid  = (ce2)? r_ring_ctrl_in.valid : '0;

	outbuf_din.data   = write_data;
   end
  
   always_ff @(posedge gclk.clk) begin
	r_ring_ctrl_in 	  <= ring_ctrl_in;
	write_data[63:32] <= ring_data_in;	
   end
   
   always_ff @(negedge gclk.clk) begin
	r_ring_din 		 <= ring_data_in;
    write_data[31:0] <= r_ring_din;
   end
	
   //ram
   always_ff @(posedge gclk.clk2x) begin
	if (we) outbuf[addr] <= outbuf_din;		
   end

   //optimized for routing and reg usage 
   //always_ff @(negedge gclk.clk) read_data <= outbuf[addr];
	//always_ff @(posedge gclk.clk2x) if (~ce2) read_data <= outbuf[addr];
	assign read_data = outbuf[io_tid];

endmodule


module perfctr_io #(parameter bit [PERFCTRADDRMSB:0] NLOCAL=2, parameter bit [PERFCTRADDRMSB:0] NGLOBAL = 2, parameter bit [3:0] addrmask = 4'b0) (input iu_clk_type gclk, input bit rst, 
                  output io_bus_out_type      bus_out,
                  input  io_bus_in_type       bus_in,
                  output bit                  bus_sel,
                  //counter signals
                  input  bit [NGLOBAL-1:0]    global_inc,
                  input  bit [NLOCAL-1:0]     local_inc,     //local increment
                  input  bit [NTHREADIDMSB:0] local_tid[0:NLOCAL-1]
                  );

perfctr_ring_ctrl_type  ring_ctrl_input[0:NLOCAL+NGLOBAL];
perfctr_ring_data_type  ring_data_input[0:NLOCAL+NGLOBAL];

perfctr_ring_ctrl_type  outbuf_ring_ctrl_input;

perfctr_ring_buf_type   read_data;

bit [NTHREADIDMSB:0]    ring_wtid[(NLOCAL+NGLOBAL)*2-1:0];

//input registers
bit [NTHREADIDMSB:0]  rtid, wtid;    //thread id
bit [IO_AWIDTH-1:0]   raddr;   //request address
bit                   io_sel;

always_ff @(posedge gclk.clk) begin
  rtid  <= bus_in.addr[IO_AWIDTH-5 -: NTHREADIDMSB+1];
  wtid  <= bus_in.tid;
  raddr <= bus_in.addr;
  io_sel <= (bus_in.addr[IO_AWIDTH-1 : IO_AWIDTH-4] == addrmask) ? '1 : '0;
  
  ring_wtid <= {wtid, ring_wtid[(NLOCAL+NGLOBAL)*2-1:1]};
end

always_comb begin
  ring_ctrl_input[0].tid  = rtid;
  ring_ctrl_input[0].addr = unsigned'(raddr[3 +: log2x(NLOCAL+NGLOBAL)]);   //request address   
  ring_ctrl_input[0].valid = bus_in.en & ~bus_in.replay & ~bus_in.rw & ~raddr[2] & io_sel;
  
  ring_data_input[0] = '0;
  
  //output buffer input (from ring)
  outbuf_ring_ctrl_input     = ring_ctrl_input[NLOCAL+NGLOBAL];
  outbuf_ring_ctrl_input.tid = ring_wtid[0];

  //output
  bus_out.irl    = '0;
  bus_out.rdata  = (raddr[2]) ? read_data.data[31:0] : read_data.data[63:32];
  bus_out.retry  = bus_in.en & io_sel & (~bus_in.replay | ~read_data.valid) & ~bus_in.rw & (~raddr[2] | ~read_data.valid);
  bus_sel = io_sel;
end

generate
  genvar i;
  
  for(i=0; i<NGLOBAL+NLOCAL; i++) begin        //generate global counter
    if (i < NGLOBAL) 
      perfctr_reg #(.IOADDR(i)) ring_perf_counter(.gclk, .rst, 
                                            .ring_ctrl_in(ring_ctrl_input[i]),
                                            .ring_data_in(ring_data_input[i]),
                                            .ring_ctrl_out(ring_ctrl_input[i+1]),
                                            .ring_data_out(ring_data_input[i+1]),
                                            .increment_en(global_inc[i]));
    else
      perfctr_ram #(.IOADDR(i)) ring_perf_counter(.gclk, .rst, 
                                            .ring_ctrl_in(ring_ctrl_input[i]),
                                            .ring_data_in(ring_data_input[i]),
                                            .ring_ctrl_out(ring_ctrl_input[i+1]),
                                            .ring_data_out(ring_data_input[i+1]),
                                            .increment_addr(local_tid[i-NGLOBAL]),
                                            .increment_en(local_inc[i-NGLOBAL]));
  end  

endgenerate


perfctr_output_buf  outbuf(.gclk, .rst, 
//               .ring_ctrl_in(ring_ctrl_input[NLOCAL+NGLOBAL]),
               .ring_ctrl_in(outbuf_ring_ctrl_input),
               .ring_data_in(ring_data_input[NLOCAL+NGLOBAL]),
               .io_tid(wtid),
               .io_we(ring_ctrl_input[0].valid),
               .read_data(read_data)
               );


endmodule