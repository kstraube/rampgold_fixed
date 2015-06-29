//---------------------------------------------------------------------------   
// File:        mmuwalk.sv
// Author:      Zhangxi Tan
// Description: mmu table walk logic
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


/*
//write @ clk2x (two writes, one from I, one from D), read @ clk
module mmuwalk_ififo(input iu_clk_type gclk, input bit rst,
                     input  mmu_walk_request_data_type    din_a,
                     input  mmu_walk_request_data_type    din_b,
                     output mmu_walk_request_data_type    dout,
                     input  bit                            we_a,
                     input  bit                            we_b,
                     input  bit                            re,
                     output bit                            luterr
                    );
      (* syn_maxfan=16 *)  bit [NTHREADIDMSB:0]            head, tail;
      (* syn_maxfan=16 *)  bit                             we, re1, re2;
      mmu_walk_request_data_type                          din, cmdqueue_do, rdo;   
      
      bit                                                  empty;
      
      (* syn_ramstyle = "select_ram" *) mmu_walk_request_data_type cmdqueue[0:NTHREAD-1];
      

      always_comb begin

        din = (gclk.ce) ? din_a : din_b;
        we = (gclk.ce) ? we_a : we_b;      

        //fifo flags
        empty = (head == tail) ? '1 : '0;
        
        re1 = re | (rdo.op == tlbmem_nop); 
        re2 = re1 & ~empty;
        
        
        //output
        dout    = rdo;
        luterr  = (LUTRAMPROT)? ^cmdqueue_do : '0;
      end
      
      //queue pointers
      always_ff @(posedge gclk.clk2x) begin
          if (rst)
            tail <= '0;
          else if ((gclk.ce & we_a) | (~gclk.ce | we_b))
            tail <=   tail+ 1;
      end
      
      always_ff @(posedge gclk.clk) begin
          if (rst) 
            head <= '0;
          else if (re2)
            head <= head + 1;
      end                  
      
      //FIFO rams
      assign cmdqueue_do = cmdqueue[head];
      always_ff @(posedge gclk.clk2x) if (we) cmdqueue[tail] <= din;
            
      
      //output registers
      always_ff @(posedge gclk.clk) begin          
          if (rst) 
            rdo.op <= tlbmem_nop; //reset              
          else (re1)
            rdo.op <= (empty)? tlbmem_nop : cmdqueue_do.op;          
            
          if (re1)begin
              rdo.isI <= cmdqueue_do.isI;   
              rdo.tid <= cmdqueue_do.tid;
              rdo.addr <= cmdqueue_do.addr;
              rdo.parity <= cmdqueue_do.parity;
          end
      end
                            
endmodule
*/

//write @ negedge clk 
module mmuwalk_buffer #(parameter int LUTRAMDDR=1) (input iu_clk_type gclk, input bit rst,
                     input  mmu_walk_request_data_type     din,
                     input  bit [NTHREADIDMSB:0]           rtid,
                     input  bit [NTHREADIDMSB:0]           wtid,
                     output mmu_walk_request_data_type     dout,
                     input  bit                            we,
                     output bit                            luterr
                    );
                    
     
      mmu_walk_request_data_type                           wdin, r_dout;             
      (* syn_maxfan=16 *)  bit [NTHREADIDMSB:0]            addr;    
      (* syn_maxfan=16 *)  bit                             ram_we;
      
      (* syn_ramstyle = "select_ram" *) mmu_walk_request_data_type walk_ram[0:NTHREAD-1];
      

      always_comb begin
        addr = (gclk.ce) ? rtid : wtid;
        
        ram_we = rst | we;
        
        wdin = din;
        if (rst) begin 
          wdin.walking = '0;
          wdin.cnt = '0;
        end
      
        luterr = (LUTRAMPROT) ? ^r_dout : '0;
        dout   = r_dout;
      end
    
      //output register
      always_ff @(posedge gclk.clk) r_dout <= (LUTRAMDDR) ? walk_ram[addr] : walk_ram[rtid];
    
      //rams
      generate 
        if (LUTRAMDDR)
          always_ff @(negedge gclk.clk) begin if (ram_we) walk_ram[addr] <= wdin; end
        else
          always_ff @(posedge gclk.clk) begin if (ram_we) walk_ram[wtid] <= wdin; end
      endgenerate
endmodule


// **************************************MMU walk timing ***********************************************
// pipeline stages           
//
//          |<------------EX2(M1)-------->|<-------------M2------------>|<------------XC-------------->|
//
// clk       ______________                ______________                ______________                 
//          |              |              |              |              |              |               
//                         ----------------              ----------------              -----------------
//           _______        _______        _______        _______        _______        _______
// clk2x    |       |      |       |      |       |      |       |      |       |      |       |
//                  --------       --------       --------       --------       --------       --------
//
//fromitlb->|<--------tlb loop up--------->
//iu2dtlb             fromdtlb,tohc
//                                         <------------$ acc----------->
//                                                                       <--------state update--------->
//                                                                                 fromhc, mmureg_in

function bit [31:2] getwalkaddress(bit [31:2] base, bit [1:0] level, bit [31:2] vaddr);
  bit [31:2]  ret_addr;
  

  unique case (level)
  2'b01:ret_addr = {base[27:2], 4'b0} | unsigned'(vaddr[31:24]);
  2'b10:ret_addr = {base[27:2], 4'b0} | unsigned'(vaddr[23:18]);
  default: ret_addr = {base[27:2], 4'b0} | unsigned'(vaddr[17:12]);  
  endcase

  return ret_addr;
endfunction


module mmuwalk (input iu_clk_type gclk, input bit rst, 
              //tlb interface
              //input mmu_itlb_mmumem_type                fromitlb,
              input mmu_iu_dtlb_type                    fromitlb,
              input mmu_dtlb_mmumem_type                fromdtlb,
              output mmu_mmumem_itlb_type               toitlb,   //@XC
              output mmu_mmumem_dtlb_type               todtlb,   //@XC
              input bit [1:0]                           next_level,       //@XC
              input bit                                 stop_walk,        //@XC
              output bit [1:0]                          current_level,    //@EX2/MEM1
              //mmureg write
              input mmureg_write_in_type                mmureg_in,
              output mmu_context_table_ptr_register_ram_type  mmureg_ctx_ptr_dout,
              //walk <-> host $ interface
              input mmu_host_cache_out_type             fromhc,
              output mmu_host_cache_in_type             tohc,
              output bit                                luterr              
              ) /* synthesis syn_sharing = "on" */;              
              
              bit [31:2]              start_walk_addr;           
              //context table pointer rams (LUTRAM for now)
              mmu_context_table_ptr_register_ram_type   ctx_ptr_dout, ctx_ptr_din;     //two read ports one write port
              bit                     ctx_ptr_luterr;         
              
              //walk state buf signals
              mmu_walk_request_data_type                walk_buf_din, walk_buf_dout;
              bit                     walk_buf_luterr;

              //outputs
              mmu_mmumem_itlb_type               v_toitlb;
              mmu_mmumem_dtlb_type               v_todtlb;

              //pipeline registers (can be shared)
              bit [MMUCTXMSB:0] delr_m1_ctx;
              struct {
                  bit [1:0]        lvl;
//                  bit [31:12]      vaddr;
              }delr_m2, delr_xc;
              
              always_comb begin                
                ctx_ptr_din = (LUTRAMPROT)? {^mmureg_in.data[31:2], mmureg_in.data[31:2]} : {1'b0, mmureg_in.data[31:2]};
                                         
                //to host $ (M1)
                tohc.tid = fromdtlb.tid;
                tohc.walk_state = tlbmem_nop;     //no use
                //tohc.walk_state = (walk_buf_dout.walking) ? tlbmem_read_miss : tlbmem_nop;     //only used for simulation (optimized away in synthesis)
                //tohc.cnt  = walk_buf_dout.cnt;  //in order to support the probe logic
                start_walk_addr = {ctx_ptr_dout.pt, 4'b0};
                start_walk_addr |= unsigned'(delr_m1_ctx);
                tohc.addr = (!walk_buf_dout.walking) ? start_walk_addr : getwalkaddress(walk_buf_dout.addr, walk_buf_dout.cnt, fromdtlb.addr); //can't use replay bit for mux control, b/c tlbflush/itlb miss may force the pipeline to replay
                
                
                //from host $ (XC)
                walk_buf_din.parity = '0;
//                walk_buf_din.isI  = fromhc.isI;                
//                walk_buf_din.op   = fromhc.walk_state;//(fromhc.data[1:0] != 1) ? tlbmem_nop : fromhc.walk_state;
                walk_buf_din.walking = (fromhc.walk_state == tlbmem_nop) ? '0 : '1;
                walk_buf_din.addr = fromhc.data[31:2];
                walk_buf_din.cnt  = next_level;  
                walk_buf_din.parity = (LUTRAMPROT) ? ^walk_buf_din : '0;

                
                //output
                mmureg_ctx_ptr_dout = ctx_ptr_dout;
                current_level  = walk_buf_dout.cnt;  //in order to support the probe logic
                
                //-->itlb
                v_toitlb.tid = fromhc.tid;
                v_toitlb.pte = fromhc.data;
                v_toitlb.lvl = delr_xc.lvl;
                //v_toitlb.large_page = (next_level < 3) ? '1 : '0;
                
                v_toitlb.op = tlb_nop;
                v_toitlb.mmureg = mmureg_in.data;
                
                v_todtlb = v_toitlb;    //default values to dtlb
                
                unique case (mmureg_in.op)
                mmureg_ctx: v_toitlb.op = update_ctx_reg;  
                mmureg_ctr: v_toitlb.op = update_ctrl_reg; 
                mmureg_iflush_all: begin 
               //           v_toitlb.mmureg[MMUCTXMSB:0] = mmureg_in.ctx;         //flush ctx                          
                          v_toitlb.op = tlb_flush_all; //else v_todtlb.op = tlb_flush_all;
                       end
                mmureg_iflush_l0 : begin 
                //          v_toitlb.mmureg[MMUCTXMSB:0] = mmureg_in.ctx;         //flush ctx                          
                          v_toitlb.op = tlb_flush_l0; //else v_todtlb.op = tlb_flush_l0;
                       end
                mmureg_iflush_l1 : begin 
                //        v_toitlb.mmureg[MMUCTXMSB:0] = mmureg_in.ctx;         //flush ctx                          
                         v_toitlb.op = tlb_flush_l1; //else v_todtlb.op = tlb_flush_l1;
                       end                       
                mmureg_iflush_l2 : begin 
                //        v_toitlb.mmureg[MMUCTXMSB:0] = mmureg_in.ctx;         //flush ctx                          
                         v_toitlb.op = tlb_flush_l2; //else v_todtlb.op = tlb_flush_l2;
                       end
                mmureg_iflush_l3 : begin 
                //        v_toitlb.mmureg[MMUCTXMSB:0] = mmureg_in.ctx;         //flush ctx                          
                         v_toitlb.op = tlb_flush_l3; //else v_todtlb.op = tlb_flush_l3;
                       end
                default : begin 
                          if (fromhc.valid && stop_walk)
                            if (fromhc.isI)
                              v_toitlb.op = tlb_refill;
                            else
                              v_todtlb.op = tlb_refill;                            
                          end
                endcase
                //update dtlb.mmureg
                v_todtlb.mmureg = v_toitlb.mmureg;                                
                
                //outputs
                todtlb = v_todtlb;
               // toitlb = v_toitlb;
                luterr = ctx_ptr_luterr | walk_buf_luterr;
              end
              
              //synthesis translate_off
               property check_tlb_refill;
               @(posedge(gclk.clk))
                disable iff (rst || ~fromhc.valid || fromhc.data[1:0] == 1) 
                  (mmureg_in.op == mmureg_nop);
              endproperty

              assert property(check_tlb_refill) else $display("Unexpected tlb refill @%t", $time);
              //synthesis translate_on
  
            
              always_ff @(posedge gclk.clk) begin
                delr_m1_ctx <= fromitlb.ctx; 
//                delr_m2_ctx <= delr_m1_ctx;
//                delr_xc_ctx <= delr_m2_ctx;

                delr_m2.lvl   <= walk_buf_dout.cnt;
//                delr_m2.vaddr <= fromdtlb.addr[31:12];
                delr_xc <= delr_m2;
                
                toitlb <= v_toitlb;
              end

              mmu_context_table_pointer_register  context_table_ptr(.gclk,
                                                                    .din(ctx_ptr_din),
                                                                    .we((mmureg_in.op == mmureg_ctx_ptr)),
                                                                    .raddr(fromitlb.tid),
//                                                                    .rctx(fromitlb.ctx),
                                                                    .waddr(mmureg_in.tid),
//                                                                    .wctx(delr_xc_ctx),
                                                                    .dout(ctx_ptr_dout),
                                                                    .luterr(ctx_ptr_luterr)
                                                                   );
                                                                   
              mmuwalk_buffer #(.LUTRAMDDR(0)) walk_state_buf(.gclk, .rst,
                     .din(walk_buf_din),      
                     .rtid(fromitlb.tid),
                     .wtid(fromhc.tid),
                     .dout(walk_buf_dout),
                     .we(fromhc.valid),
                     .luterr(walk_buf_luterr)
                    );
              
endmodule