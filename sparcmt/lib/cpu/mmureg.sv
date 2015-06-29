//---------------------------------------------------------------------------   
// File:        mmureg.sv
// Author:      Zhangxi Tan
// Description: mmu special registers
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libmmu::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`endif

module mmu_control_register #(parameter int DOREG=1) (input iu_clk_type gclk,
                                input   mmu_control_register_ram_type din,
                                input   bit [NTHREADIDMSB:0]          wtid,
                                input   bit                           we, 
                                input   bit [NTHREADIDMSB:0]          rtid,
                                output  mmu_control_register_ram_type dout, 
                                output  bit                           luterr);
       (* syn_ramstyle = "select_ram" *)  mmu_control_register_ram_type ctrl_reg[0:NTHREAD-1];
       mmu_control_register_ram_type    w_dout, r_dout;
       always_comb begin
         w_dout  = ctrl_reg[rtid];         

         luterr = (LUTRAMPROT)? ((DOREG)? ^r_dout :^w_dout) : '0;         
         dout  = (DOREG) ? r_dout : w_dout;
       end       
	   
       always_ff @(posedge gclk.clk) begin
          if (we) ctrl_reg[wtid] <= din;
		  
		  r_dout <= w_dout;
       end
	   	  
endmodule

module mmu_context_register #(parameter int DOREG=1) (input iu_clk_type gclk, 
                                input   mmu_context_register_ram_type din,
                                input   bit [NTHREADIDMSB:0]          wtid,
                                input   bit                           we, 
                                input   bit [NTHREADIDMSB:0]          rtid,
                                output  mmu_context_register_ram_type dout, 
                                output  bit                           luterr);
       (* syn_ramstyle = "select_ram" *)  mmu_context_register_ram_type ctx_reg[0:NTHREAD-1];
       mmu_context_register_ram_type    w_dout, r_dout;

       always_comb begin
         w_dout  = ctx_reg[rtid];         

         luterr = (LUTRAMPROT)? ((DOREG) ? ^r_dout : ^w_dout) : '0;         
         dout  = (DOREG) ? r_dout : w_dout;
       end
       
       always_ff @(posedge gclk.clk) begin
          if (we) ctx_reg[wtid] <= din;
		  r_dout <= w_dout;
       end
	   
endmodule

/*
module mmu_context_table_pointer_register(input iu_clk_type gclk,
                                      input mmu_context_table_ptr_register_ram_type  din,
                                      input bit                                      we_b,
                                      input bit [NTHREADIDMSB:0]                     tid_a,
                                      input bit [MMUCTXMSB:0]                        ctx_a,
                                      input bit [NTHREADIDMSB:0]                     tid_b,
                                      input bit [MMUCTXMSB:0]                        ctx_b,
                                      output mmu_context_table_ptr_register_ram_type dout, 
                                      output bit                                     luterr);

    (* syn_ramstyle= "select_ram" *)  mmu_context_table_ptr_register_ram_type   ctx_ptr[0:NTHREAD*MMUCTXNUM-1];     //two read ports one write port
     (* syn_maxfan = 16 *) bit [log2x(NTHREAD*MMUCTXNUM)-1:0]    addr;   //TDM address     
     mmu_context_table_ptr_register_ram_type                     r_dout;    
     
      always_comb begin 
        addr =  (gclk.ce) ? {tid_a, ctx_a} : {tid_b, ctx_b};        
        dou    = r_dout;      
        luterr = (LUTRAMPROT) ? ^r_dout : '0;
      end
      //context pointer ram
      always_ff @(negedge gclk.clk)  if (we_b) ctx_ptr[addr] <= din;                                     
      always_ff @(posedge gclk.clk2x)  r_dout <= ctx_ptr[addr];
endmodule                                      
*/

module mmu_context_table_pointer_register(input iu_clk_type gclk,
                                      input mmu_context_table_ptr_register_ram_type  din,
                                      input bit                                      we,
                                      input bit [NTHREADIDMSB:0]                     raddr,
//                                      input bit [MMUCTXMSB:0]                        rctx,
                                      input bit [NTHREADIDMSB:0]                     waddr,
//                                      input bit [MMUCTXMSB:0]                        wctx,
                                      output mmu_context_table_ptr_register_ram_type dout,                                       
                                      output bit                                     luterr);

    (* syn_ramstyle= "select_ram" *)  mmu_context_table_ptr_register_ram_type   ctx_ptr[0:NTHREAD-1];     //one read port one write port     
     mmu_context_table_ptr_register_ram_type                     r_dout;          //This maybe retimed
     
      always_comb begin   
        dout   = r_dout;      
        luterr = (LUTRAMPROT) ? ^r_dout : '0;
      end
      //context pointer ram
      always_ff @(posedge gclk.clk)  if (we) ctx_ptr[waddr] <= din;                                     
      always_ff @(posedge gclk.clk)  r_dout <= ctx_ptr[raddr];
endmodule                                      

module mmu_fault_status_register(input iu_clk_type gclk, input bit rst,
                                input mmu_fault_status_register_ram_type  din,
                                input bit                                      we,
                                input bit [NTHREADIDMSB:0]                     rtid,
                                input bit [NTHREADIDMSB:0]                     wtid,
                                output mmu_fault_status_register_ram_type dout,                                       
                                output bit                                     luterr);
	(* syn_ramstyle= "select_ram" *)  mmu_fault_status_register_ram_type   fs[0:NTHREAD-1];     //two read ports one write port     
     mmu_fault_status_register_ram_type                     r_dout;          //r_dout maybe retimed
     
      always_comb begin   
        dout   = r_dout;      
        luterr = (LUTRAMPROT) ? ^r_dout : '0;
	  end
      //context pointer ram
      always_ff @(posedge gclk.clk)  if (we) fs[wtid] <= din;                                     
      always_ff @(posedge gclk.clk)  r_dout <= fs[rtid];
endmodule								

module mmu_fault_address_register(input iu_clk_type gclk, input bit rst,
                                input mmu_fault_address_register_ram_type  din,
                                input bit                                      we,
                                input bit [NTHREADIDMSB:0]                     rtid,
                                input bit [NTHREADIDMSB:0]                     wtid,
                                output mmu_fault_address_register_ram_type dout,                                       
                                output bit                                     luterr);
	(* syn_ramstyle= "select_ram" *)  mmu_fault_address_register_ram_type   faddr[0:NTHREAD-1];     //two read ports one write port     
     mmu_fault_address_register_ram_type                     r_dout;          //r_dout maybe retimed
     
      always_comb begin   
        dout    = r_dout;      
        luterr = (LUTRAMPROT) ? ^r_dout : '0;
	  end
      //context pointer ram
      always_ff @(posedge gclk.clk)  if (we) faddr[wtid] <= din;                                     
      always_ff @(posedge gclk.clk)  r_dout <= faddr[rtid];
endmodule								
