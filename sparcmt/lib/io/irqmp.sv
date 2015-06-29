//---------------------------------------------------------------------------   
// File:        irqmp.sv
// Author:      Zhangxi Tan
// Description: Multicore IRQ controller 
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps
`ifndef SYNP94
import libconf::*;
import libiu::*;
import libio::*;
`else
`include "../cpu/libiu.sv"
`include "libio.sv"
`endif


module irqmp #(parameter NIRQ=2, parameter bit [3:0] addrmask = 4'b0 ) (input iu_clk_type gclk, input bit rst, 
             // CPU interface
             input  io_bus_in_type       bus_in,
             input  bit                  irqack,              //@xc
             output io_bus_out_type      bus_out,
             // IO bus device interface
             input  bit [NIRQ-1:0]       irq                  //@M2
            );
            
            //ipi has the highest priority
            (* syn_ramstyle = "select_ram" *) bit               ipi_ram[0:NTHREAD-1];           //no need to protect it from SEU, just take a trap          
            bit                   ipi_dout, ipi_din;
            bit [NTHREADIDMSB:0]  ipi_waddr;
            bit                   ipi_we;
            
            (* syn_ramstyle = "select_ram" *) bit [NIRQ-1:0]    irq_pending_ram[0:NTHREAD-1];    
            bit  [NIRQ-1:0] irq_pending_dout, irq_pending_din;// irq_sel;
//            bit             irq_pending_we;

            (* syn_ramstyle = "select_ram" *) bit [3:0]    irl_ram[0:NTHREAD-1];    
            bit [3:0]    irl_dout;

                        
            (* syn_maxfan = 16 *) struct {
              bit [NTHREADIDMSB:0] tid;
              bit [NTHREADIDMSB:0] ipi_tid;
              bit                  ipi_valid;
//              bit                  new_ipi;
            }delr_m2, v_delr_m2;
            
            (* syn_maxfan = 16 *) struct {
              bit [NTHREADIDMSB:0] tid;
              bit [NTHREADIDMSB:0] ipi_tid;
              bit                  ipi_valid;
              
              bit [NIRQ-1:0]       irq_sel;
              bit [NIRQ-1:0]       irq_new, irq_pending;               
              bit                  irq_pending_we;
            }delr_xc, v_delr_xc;
            

            integer i;      //loop variable
            
            const bit [3:0]     irq_table[0:14] = {4'd10, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0, 4'd0};
                        
            always_comb begin
              //m1: decode software
              v_delr_m2.tid = bus_in.tid;
//              v_delr_m2.ipi_tid = bus_in.addr[2 +: NTHREADIDMSB+1];              
              v_delr_m2.ipi_tid = bus_in.addr[IO_AWIDTH-5 -: NTHREADIDMSB+1];              
              
              v_delr_m2.ipi_valid = (bus_in.addr[IO_AWIDTH-1 : IO_AWIDTH-4] == addrmask) ? '1 : '0;      
//              v_delr_m2.new_ipi = (bus_in.addr[IO_AWIDTH-5 -: NTHREADIDMSB+1] == bus_in.tid) ? v_delr_m2.ipi_valid : '0;
              
              bus_out.irl = irl_ram[bus_in.tid];
              
              //m2            
              v_delr_xc.tid = delr_m2.tid;
              v_delr_xc.ipi_tid = delr_m2.ipi_tid;
              v_delr_xc.ipi_valid = delr_m2.ipi_valid & bus_in.rw & bus_in.en;
              
              irl_dout = '0;
              v_delr_xc.irq_new = irq;
              v_delr_xc.irq_pending = irq_pending_dout;
              v_delr_xc.irq_sel = '0;   
              v_delr_xc.irq_pending_we = bus_in.wtid_valid;
              
              i= NIRQ - 1;              
              do begin
                if (ipi_dout) begin               
                  irl_dout = 4'd14;
                  i = '0;                  
                end
                else if (irq_pending_dout[i]) begin
                  irl_dout = irq_table[i];
                  v_delr_xc.irq_sel[i] = '1;
                  i = '0;
                end                  
                i--;
              end
              while (i > 0);              
                                          
              bus_out.retry = '0;   //no use
              bus_out.rdata = '0;   //no use

              //xc: write back stage
              /*
              ipi_we = (gclk.ce) ? delr_xc.ipi_valid : irqack;
              
              ipi_waddr = (gclk.ce) ? delr_xc.ipi_tid : delr_xc.tid; 
              ipi_din = (~gclk.ce | rst) ? '0 : '1;
              */
              ipi_we = ((gclk.ce) ? irqack : delr_xc.ipi_valid) | rst;				//MCP: irqack -> ipi ram 
              
              ipi_waddr = (gclk.ce) ? delr_xc.tid : delr_xc.ipi_tid; 
              ipi_din = (gclk.ce | rst) ? '0 : '1;

              
              if (rst)
                irq_pending_din = '0;
              else if (irqack)
                irq_pending_din = ((delr_xc.irq_pending | delr_xc.irq_new) & ~delr_xc.irq_sel); // | (delr_xc.irq_sel & delr_xc.irq_new);
              else
                irq_pending_din = delr_xc.irq_pending | delr_xc.irq_new;

            end
            
            always_ff @(posedge gclk.clk) begin
              delr_m2 <= v_delr_m2;
              delr_xc <= v_delr_xc;
            end
            
            //irl ram
            always_ff @(posedge gclk.clk) irl_ram[delr_m2.tid] <= irl_dout;
            //ipi ram
            always_ff @(posedge gclk.clk2x) if (ipi_we) ipi_ram[ipi_waddr] <= ipi_din;
            always_ff @(posedge gclk.clk2x) if (gclk.ce) ipi_dout <= ipi_ram[bus_in.tid];
            
            //irq pending ram
            always_ff @(posedge gclk.clk) if (delr_xc.irq_pending_we) irq_pending_ram[delr_xc.tid] <= irq_pending_din;              
            always_ff @(posedge gclk.clk) irq_pending_dout <= irq_pending_ram[bus_in.tid];
            

endmodule