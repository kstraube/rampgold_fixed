//---------------------------------------------------------------------------   
// File:        debugdma.v
// Author:      Zhangxi Tan
// Description: Data structures for onchip debuging: 
//              Initialization DMA engine
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libdebug::*;
`else
`include "libiu.sv"
//`include "libdebug.sv"
`endif

module dma_addr_reg (input iu_clk_type gclk, 
                    input bit [NTHREADIDMSB:0]        dma_wtid,
                    input bit                         dma_we,      
                    input debug_dma_addr_reg_type     dma_wdata,
                    input bit [NTHREADIDMSB:0]        iu_wtid,
                    input bit                         iu_we,
                    input debug_dma_addr_reg_type     iu_wdata,
                    input bit [NTHREADIDMSB:0]        iu_rtid,
                    output debug_dma_addr_reg_type    iu_rdata
                    );
   (* syn_ramstyle = "select_ram" *)  debug_dma_addr_reg_type   addrmem[0:NTHREAD-1];
   (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]     /*addr,*/ raddr, waddr;       //TDM addr;
   bit                      we;         //TDM WE
   debug_dma_addr_reg_type  wdata;      //TDM write data               
  // debug_dma_addr_reg_type  rdata;
   
  
 /*  always_comb begin    
        wdata = (iu_we) ? iu_wdata : dma_wdata;          
        we    = iu_we | dma_we;  
        
        if (gclk.ce) begin   //posedge
          addr  = (iu_we) ? iu_wtid : dma_wtid;             
        end
        else begin
          addr = iu_rtid;
        end
   end 

   assign rdata = addrmem[addr];
      
   //always_ff @(negedge gclk.clk) begin
   always_ff @(posedge gclk.clk2x) begin
      if (!gclk.ce) iu_rdata <= rdata;
   end
   
//   always_ff @(posedge gclk.clk) begin
   always_ff @(posedge gclk.clk2x) begin
      if (we & gclk.ce) addrmem[addr] <= wdata;
   end */
   
   always_comb begin 
     wdata = (gclk.ce) ? iu_wdata : dma_wdata;
     we    = (gclk.ce) ? iu_we   : dma_we;     
     waddr = (gclk.ce) ? iu_wtid : dma_wtid;
     raddr = iu_rtid;     
   end  
   
   always_ff @(posedge gclk.clk2x) begin
      if (!gclk.ce) iu_rdata <= addrmem[raddr];     //this register can be removed if MCP constraints are properly set
        
      if (we) addrmem[waddr] <= wdata;
   end
endmodule                  

module dma_ctrl_reg(input iu_clk_type gclk, input bit rst,                    
                    input bit [NTHREADIDMSB:0]        dma_wtid,
                    input bit                         dma_we,      
                    input debug_dma_ctrl_reg_type     dma_wdata,
                    output bit                        cmd_ack,                    
                    input bit [NTHREADIDMSB:0]        iu_wtid,
                    input bit                         iu_we,
                    input debug_dma_ctrl_reg_type     iu_wdata,
                    input bit [NTHREADIDMSB:0]        iu_rtid,
                    output debug_dma_ctrl_reg_type    iu_rdata                    
                    );
   (* syn_ramstyle = "select_ram" *)  debug_dma_ctrl_reg_type   ctrlmem[0:NTHREAD-1];
   (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]     /*addr*/ raddr, waddr;       //TDM addr;
   bit                      we;         //TDM WE
   debug_dma_ctrl_reg_type  wdata;      //TDM write data               
//   debug_dma_ctrl_reg_type  rdata;
   
/*  
   always_comb begin
        wdata    = (iu_we) ? iu_wdata : dma_wdata;          
        we       = iu_we | dma_we | rst;  
        cmd_ack  = ~iu_we & dma_we;
        
        if (rst)
          wdata.cmd = dma_NOP;
          
        if (gclk.ce) begin   //posedge
          addr  = (iu_we | rst) ? iu_wtid : dma_wtid;             
        end
        else begin
          addr = iu_rtid;
        end
   end

   assign rdata = ctrlmem[addr];
      
//   always_ff @(negedge gclk.clk) begin
	always_ff @(posedge gclk.clk2x) begin
	  if (!gclk.ce) iu_rdata <= rdata;
   end
   
//   always_ff @(posedge gclk.clk) begin
     always_ff @(posedge gclk.clk2x) begin
      if (we & gclk.ce) ctrlmem[addr] <= wdata;
   end   
*/
  always_comb begin
       wdata    = (gclk.ce) ? iu_wdata : dma_wdata;          
       we       = ((gclk.ce) ? iu_we : dma_we) | rst;  
       cmd_ack  = dma_we;     //dual port, always ack
       
       if (rst)
         wdata.cmd = dma_NOP;
       
       waddr = (gclk.ce | rst)? iu_wtid : dma_wtid;  
       raddr = iu_rtid;
  end

  
  always_ff @(posedge gclk.clk2x) begin
    if (!gclk.ce) iu_rdata <= ctrlmem[raddr]; //this register can be removed if MCP constraints are properly set

    if (we) ctrlmem[waddr] <= wdata;
  end 
endmodule

  
module debug_dma(input iu_clk_type gclk, input rst,
                 //iu interface
                 input  bit [NTHREADIDMSB:0]            dma_rtid,     //read thread ID
                 input  debug_dma_in_type               iu2dma,
                 output debug_dma_out_type              dma2iu,
                 //buffer interface
                 output debug_dma_read_buffer_in_type   dma_rb_in,
                 input  debug_dma_read_buffer_out_type  dma_rb_out,
                 output debug_dma_write_buffer_in_type  dma_wb_in,
                 //command interface 
                 input  debug_dma_cmdif_in_type         dma_cmd_in,     //cmd input 
                 output bit                             dma_cmd_ack,    //cmd has been accepted
                 //dma status
                 output bit                             dma_done,
                 //error reporting
                 output bit  luterr
                 );
      debug_dma_addr_reg_type     v_new_addr_reg, r_new_addr_reg;      //new addr reg (updated by IU)
      debug_dma_ctrl_reg_type     v_new_ctrl_reg, r_new_ctrl_reg;      //new ctrl reg
      
      //dma register outputs
      debug_dma_addr_reg_type     addr_reg, n_addr_reg;
      debug_dma_ctrl_reg_type     ctrl_reg, n_ctrl_reg;
      
            
      //pipeline registers for iu2dma           
      debug_dma_in_type           fromiu;       //pipeline register
      bit [NTHREADIDMSB:0]        iu_wtid;
      bit                         iu_we;

      //used for LUTRAM parity error report
      bit                         addr_reg_error, ctrl_reg_error;
      
      always_comb begin          //dma address calculation
        v_new_addr_reg.addr   = fromiu.state.addr + 1;                    //32-bit address
        v_new_addr_reg.parity = (LUTRAMPROT) ? ^v_new_addr_reg.addr : '0;
        
        v_new_ctrl_reg.parity   = '0;                                       //default valude
        v_new_ctrl_reg.buf_addr = fromiu.state.buf_addr + 1;
        v_new_ctrl_reg.count    = fromiu.state.count - 1;
        v_new_ctrl_reg.cmd      = (fromiu.done)? dma_NOP : fromiu.state.cmd;
        v_new_ctrl_reg.parity   = (LUTRAMPROT)? ^v_new_ctrl_reg : '0;        
      end

      function debug_dma_in_type pipelining_iu2dma();
         debug_dma_in_type    v_fromiu;
         
         v_fromiu = iu2dma;
         if (rst)
           v_fromiu.state.cmd = dma_NOP;
         
         return v_fromiu;
      endfunction
           
      //tx
      always_comb begin
        dma_wb_in.addr   = fromiu.state.buf_addr;
        dma_wb_in.data   = fromiu.state.data;
		    dma_wb_in.parity = (BRAMPROT) ? ^fromiu.state.data : '0;
       // dma_wb_in.we = (fromiu.state.cmd == dma_LD || fromiu.state.cmd == dma_FMT3) ? fromiu.ack : '0;          
        dma_wb_in.we = (fromiu.state.cmd == dma_OP) ? fromiu.ack : '0;       //if ST, flush, write back data is undefined.
        dma_done = fromiu.done;
      end
      
      //rx
      always_comb begin
        dma_rb_in.addr  = n_ctrl_reg.buf_addr;
		    dma_rb_in.we	   = '0;				//no use
		    dma_rb_in.data  = '0;				//no use
		    dma_rb_in.inst  = '0;				//no use
		
        //iu input
        dma2iu.state.addr     = addr_reg.addr; 
        dma2iu.state.data     = dma_rb_out.data;
        dma2iu.state.buf_addr = ctrl_reg.buf_addr;
        dma2iu.state.count    = ctrl_reg.count;
        dma2iu.state.cmd      = ctrl_reg.cmd;
        
        //Retiming: please work hard here!
        /*
        unique case(ctrl_reg.cmd)
        dma_LD  : dma2iu.inst = {LDST, 5'b0, LD, 5'b0, 1'b1, 13'b0 };
        dma_ST  : dma2iu.inst = {LDST, 5'b0, ST, 5'b0, 1'b1, 13'b0 };
        default : dma2iu.inst = dma_rb_out.inst;
        endcase        
        */
        
        dma2iu.inst = dma_rb_out.inst;
      end 
      
      //sequential part
      always_ff @(posedge gclk.clk) begin
        fromiu <= pipelining_iu2dma();      //pipeline register for inputs from iu
        
        //shaping: convert negedge to posedge
        addr_reg <= n_addr_reg;
        ctrl_reg <= n_ctrl_reg;
        
        r_new_ctrl_reg <= v_new_ctrl_reg;
        r_new_addr_reg <= v_new_addr_reg;

        iu_wtid <= fromiu.tid;
        iu_we   <= fromiu.ack;
        
        if (LUTRAMPROT) begin
          addr_reg_error <= ^addr_reg;
          ctrl_reg_error <= ^ctrl_reg;
          
          luterr <= addr_reg_error | ctrl_reg_error;
        end
       	else begin
          addr_reg_error <= '0;
          ctrl_reg_error <= '0;
          
          luterr <= '0;		
	      end
      end
      
      dma_ctrl_reg      inst_ctrl_reg(.gclk, .rst,                    
                                      .dma_wtid(dma_cmd_in.tid),
                                      .dma_we(dma_cmd_in.ctrl_we),      
                                      .dma_wdata(dma_cmd_in.ctrl_reg),
                                      .cmd_ack(dma_cmd_ack),          //ack to the dma control reg writer
                                      .iu_wtid,
                                      .iu_we,
                                      .iu_wdata(r_new_ctrl_reg),
                                      .iu_rtid(dma_rtid),
                                      .iu_rdata(n_ctrl_reg)           //negedge registered output
                          );
      
      dma_addr_reg      inst_addr_reg(.gclk,                    
                                      .dma_wtid(dma_cmd_in.tid),
                                      .dma_we(dma_cmd_in.addr_we),      
                                      .dma_wdata(dma_cmd_in.addr_reg),
                                      .iu_wtid,
                                      .iu_we,
                                      .iu_wdata(r_new_addr_reg),
                                      .iu_rtid(dma_rtid),
                                      .iu_rdata(n_addr_reg)           //negedge registered output
                          );

                 
endmodule
               
                 