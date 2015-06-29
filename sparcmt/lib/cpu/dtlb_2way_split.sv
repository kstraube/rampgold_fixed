//---------------------------------------------------------------------------   
// File:        dtlbram_2way_split.sv
// Author:      Zhangxi Tan
// Description: 2-way set assoc. TLB. Split large and small pages 
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libmmu::*;
import libstd::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`endif


module dtlbram_2way_split #(parameter int LUTRAMDDR=1, parameter DTLBDOREG=1) (input iu_clk_type gclk, input bit rst, 
             //input from IU
             input  mmu_iu_dtlb_type      iu2tlb,    // @EX1
//             input  bit [MMUCTXMSB:0]	    ctx,		     // @ EX2/MEM1 ctx ID
             input  bit                   dirty,     // @ EX2/MEM1
             input  bit                   valid,     // @ EX2/MEM1 write to tlb?
             input  mmu_tlb_flush_probe_type    tlbflush,		//@ EX2/MEM1
             //intput from mem (only used for pte refill) @ XC 
             input  mmu_mmumem_dtlb_type  mem2tlb,                          
             //output to IU
             output mmu_dtlb_iu_type      tlbram2iu, // @EX2/MEM1             
             output bit                   sberr,
             output bit                   dberr
            )/* synthesis syn_sharing = "off" */;
             
			 /*
             typedef struct packed {
                bit [1:0]                       nway;
                bit                             wb;          
               //can be shared with some regs in mem and xc
                bit [DTLBINDEXMSB:DTLBINDEXLSB]	index;        
                mmu_dtlb_tag_type               tag;          
             }tlbram_state_type;
             */ 
			       /*struct {			    
               //can be shared with some regs in mem and xc
                bit [DTLBINDEXMSB:DTLBINDEXLSB]	index;        				
                bit [31:DTLBTAGLSB]             vpn_tag;
                bit [MMUCTXMSB:0]				           ctx;			//may be shared by some pipe registers in the main pipeline
//            				bit								                     dirty;
        			 }delr_mem1; */
					 mmu_iu_dtlb_type		delr_ex2, delr_mem1;
			 
        			 struct {
            				bit [DTLBINDEXMSB:DTLBINDEXLSB]	index, index1;        
            				bit [MMUCTXMSB:0]				           ctx;			//may be shared by some pipe registers in the main pipeline
                bit [31:DTLBTAGLSB]             vpn_tag;
            				bit								                     dirty;
				        bit [1:0]						                 lru;
            				bit [1:0]						                 flush_small, flush_large;
            				bit                             update_small_lru, update_large_lru;
          						bit												            valid;
        			 }delr_mem2, delr_xc;			 
			
             //pipeline registers            
             //tlbram_state_type                      delr_mem1, delr_mem2, delr_xc;

             //tlb bram interface signals
             mmu_dtlbram_addr_type tlbram_large_raddr, tlbram_large_waddr, tlbram_small_raddr, tlbram_small_waddr;
             mmu_dtlbram_data_type tlb_large[0:1], tlb_small[0:1], tlbram_small_din, tlbram_large_din;        
             bit [3:0]             tlb_sberr, tlb_dberr;
			       bit [1:0]			          tlb_large_we, tlb_small_we;
             
               (* syn_maxfan=8 *) bit [1:0]             tlb_large_hit, tlb_small_hit, l1_hit;
//             bit                   tlb_hit;
             
             //lru lutram
             (* syn_ramstyle = "select_ram" *)  bit lru_ram_small[0:NTHREAD*NDTLBENTRY-1], lru_ram_large[0:NTHREAD*NDTLBENTRY-1];   //one read port one write port (use dual port ram for higher performance)			 
             bit                   lru_we_small, lru_we_large;          //write enable
             bit                   r_small_lru, r_large_lru;

             
             always_comb begin                                                              
                //tlb bram signals
                tlbram_small_raddr.tid   = iu2tlb.tid;
                tlbram_small_raddr.index = iu2tlb.index;                                                              
                tlbram_small_waddr.tid   = mem2tlb.tid;
                tlbram_small_waddr.index = delr_xc.index;                
                
                tlbram_large_raddr.tid   = iu2tlb.tid;
                tlbram_large_raddr.index = iu2tlb.index1;                                                              
                tlbram_large_waddr.tid   = mem2tlb.tid;
                tlbram_large_waddr.index = delr_xc.index1;                

                
                tlbram_small_din.data  	   	 = mem2tlb.pte;
                tlbram_small_din.data.et     = 2;
                tlbram_small_din.tag.vpn_tag = delr_xc.vpn_tag;                
				        tlbram_small_din.tag.ctx	 = delr_xc.ctx;
				        tlbram_small_din.tag.valid   = ~(|delr_xc.flush_small);
                tlbram_small_din.tag.dirty   = delr_xc.dirty;
                tlbram_small_din.tag.lvl  = 3;
//				        tlbram_small_din.tag.lru	 = delr_xc.lru[0];
				
				        tlbram_large_din 		   = tlbram_small_din;
				        tlbram_large_din.tag.lvl = mem2tlb.lvl;
				        tlbram_large_din.tag.vpn_tag[DTLBLARGETAGLSB-1: DTLBTAGLSB] = '0;   //no use for large tlb
				        tlbram_large_din.tag.valid =  ~(|delr_xc.flush_large);
//				        tlbram_large_din.tag.lru   = delr_xc.lru[1];
				
				        tlb_large_we = '0; tlb_small_we = '0;
                if (mem2tlb.op == tlb_refill && mem2tlb.pte.et == 2) begin
                  tlb_small_we[0] = &mem2tlb.lvl & ~delr_xc.lru[0] & delr_xc.valid;		//only one lru bit is needed 
                  tlb_small_we[1] = &mem2tlb.lvl & delr_xc.lru[0] & delr_xc.valid;

                  tlb_large_we[0] = ~(&mem2tlb.lvl) & ~delr_xc.lru[1] & delr_xc.valid;
                  tlb_large_we[1] = ~(&mem2tlb.lvl) & delr_xc.lru[1] & delr_xc.valid;
                end
                tlb_small_we |= delr_xc.flush_small;
				        tlb_large_we |= delr_xc.flush_large;                
				
                //tlb hit logic
                l1_hit[0] = (tlb_large[0].tag.vpn_tag[31:24] == delr_mem1.vpn_tag[31:24] && tlb_large[0].tag.ctx == delr_mem1.ctx) ? tlb_large[0].tag.valid : '0;
                l1_hit[1] = (tlb_large[1].tag.vpn_tag[31:24] == delr_mem1.vpn_tag[31:24] && tlb_large[1].tag.ctx == delr_mem1.ctx) ? tlb_large[1].tag.valid : '0;

                unique case (tlb_large[0].tag.lvl)
                0: tlb_large_hit[0] = tlb_large[0].tag.valid;
                1: tlb_large_hit[0] = l1_hit[0]; 
                2: tlb_large_hit[0] = l1_hit[0] & (tlb_large[0].tag.vpn_tag[23:DTLBLARGETAGLSB] == delr_mem1.vpn_tag[23:DTLBLARGETAGLSB]);
                default: tlb_large_hit[0] = '0;   //not possible
                endcase

                unique case (tlb_large[1].tag.lvl)
                0: tlb_large_hit[1] = tlb_large[1].tag.valid;
                1: tlb_large_hit[1] = l1_hit[1]; 
                2: tlb_large_hit[1] = l1_hit[1] & (tlb_large[1].tag.vpn_tag[23:DTLBLARGETAGLSB] == delr_mem1.vpn_tag[23:DTLBLARGETAGLSB]);
                default: tlb_large_hit[1] = '0;   //not possible
                endcase
                
                //tlb_large_hit[0] = (tlb_large[0].tag.vpn_tag == delr_mem1.vpn_tag && tlb_large[0].tag.ctx == delr_mem1.ctx) ? tlb_large[0].tag.valid : '0;
                //tlb_large_hit[1] = (tlb_large[1].tag.vpn_tag == delr_mem1.vpn_tag && tlb_large[1].tag.ctx == delr_mem1.ctx) ? tlb_large[1].tag.valid : '0;              

                tlb_small_hit[0] = (tlb_small[0].tag.vpn_tag == delr_mem1.vpn_tag && tlb_small[0].tag.ctx == delr_mem1.ctx) ? tlb_small[0].tag.valid : '0;
                tlb_small_hit[1] = (tlb_small[1].tag.vpn_tag == delr_mem1.vpn_tag && tlb_small[1].tag.ctx == delr_mem1.ctx) ? tlb_small[1].tag.valid : '0;
                
                //tlb result to IU
                if (tlb_small_hit[0]) begin
                  tlbram2iu.pte = tlb_small[0].data;
                  tlbram2iu.lvl = 3;
                end
                else if (tlb_small_hit[1]) begin
                  tlbram2iu.pte = tlb_small[1].data;
                  tlbram2iu.lvl = 3;
                end
                else if (tlb_large_hit[0]) begin
                  tlbram2iu.pte = tlb_large[0].data;
                  tlbram2iu.lvl = tlb_large[0].tag.lvl;
                end
                else begin
                  tlbram2iu.pte = tlb_large[1].data;
                  tlbram2iu.lvl = tlb_large[1].tag.lvl;
                end
                
                tlbram2iu.valid = |{tlb_small_hit, tlb_large_hit};
                
                lru_we_small = (|tlb_small_we) | delr_xc.update_small_lru;
                lru_we_large = (|tlb_large_we) | delr_xc.update_large_lru;

                
                //ram errors
                sberr = (BRAMPROT) ? |tlb_sberr : '0;
                dberr = (BRAMPROT) ? |tlb_dberr : '0;
             end
             
             //synthesis translate_off
             covergroup cg_dtlb @(posedge gclk.clk);
              tlb_small_hit_0 : coverpoint tlb_small_hit[0] iff (!rst && valid);
              tlb_small_hit_1 : coverpoint tlb_small_hit[1] iff (!rst && valid);
              tlb_large_hit_0 : coverpoint tlb_large_hit[0] iff (!rst && valid);
              tlb_large_hit_1 : coverpoint tlb_large_hit[1] iff (!rst && valid);
              tlb_small_we_0 : coverpoint tlb_small_we[0] iff (!rst);
              tlb_small_we_1 : coverpoint tlb_small_we[1] iff (!rst);
              tlb_large_we_0 : coverpoint tlb_large_we[0] iff (!rst);
              tlb_large_we_1 : coverpoint tlb_large_we[1] iff (!rst);
              tlb_small_read_index : coverpoint tlbram_small_raddr.index iff (!rst && valid);
              tlb_large_read_index : coverpoint tlbram_large_raddr.index iff (!rst && valid);
              tlb_small_write_index : coverpoint tlbram_small_raddr.index iff (!rst && |tlb_small_we);
              tlb_large_write_index : coverpoint tlbram_large_raddr.index iff (!rst && |tlb_large_we);
             endgroup
  
             cg_dtlb dtlb_stat = new;

             property assert_tlb_large;
                 @(posedge(gclk.clk))
                   disable iff (rst) 
                         ((tlb_large[0].tag.lvl != 3 && tlb_large[0].tag.valid) || !tlb_large[0].tag.valid) && ((tlb_large[1].tag.lvl != 3 && tlb_large[1].tag.valid) || !tlb_large[1].tag.valid);
             endproperty
             
             property assert_tlb_small;
                 @(posedge(gclk.clk))
                   disable iff (rst) 
                         ((tlb_small[0].tag.lvl == 3 && tlb_small[0].tag.valid) || !tlb_small[0].tag.valid) && ((tlb_small[1].tag.lvl == 3 && tlb_small[1].tag.valid) || !tlb_small[1].tag.valid);  
             endproperty
             
             property assert_tlb_hit;
                @(posedge (gclk.clk)) 
                  disable iff (rst || !valid)
                    ((|tlb_small_hit && |tlb_large_hit) == 0);
             endproperty
             
             assert property(assert_tlb_large) else $display("@%t found an invalid entry in large_dtlb", $time);
             assert property(assert_tlb_small) else $display("@%t found an invalid entry in small_dtlb", $time);
             assert property(assert_tlb_hit)  else $display ("@%t both large and small dtlb hit", $time);
            //synthesis translate_on
                 
             //pipeline registers
             always_ff @(posedge gclk.clk) begin
          				/*delr_mem1.index   <= iu2tlb.index;        
          				delr_mem1.vpn_tag <= iu2tlb.vpn_tag; 
          				delr_mem1.ctx     <= iu2tlb.ctx; */
						
						  if (DTLBDOREG) begin
                delr_ex2  <= iu2tlb;
						    delr_mem1 <= delr_ex2;
						  end
						  else
						    delr_mem1 <= iu2tlb;			//tid field will be optimized away
 //         				delr_mem1.dirty	  <= iu2tlb.m;	//in case we implement dirty bit write back                
                
          				delr_mem2.valid	 <= valid;
						  delr_mem2.index	  <= delr_mem1.index;        
						  delr_mem2.index1  <= delr_mem1.index1;      //large index
          				delr_mem2.vpn_tag <= delr_mem1.vpn_tag;
              delr_mem2.dirty	  <= dirty;
          				delr_mem2.ctx	  <= delr_mem1.ctx;					//new ctx in tag				          				
          				//need some retiming here
          				delr_mem2.lru[0]  <= get_new_2way_lru(tlb_small_hit, {tlb_small[1].tag.valid, tlb_small[0].tag.valid}, r_small_lru);	
          				delr_mem2.lru[1]  <= get_new_2way_lru(tlb_large_hit, {tlb_large[1].tag.valid, tlb_large[0].tag.valid}, r_large_lru);	
          				
          				delr_mem2.update_small_lru <= (|tlb_small_hit) & valid;
          				delr_mem2.update_large_lru <= (|tlb_large_hit) & valid;
          				
          				delr_mem2.flush_small[0] <= tlb_flush_match(tlbflush, tlb_small[0].data, tlb_small[0].tag.ctx, {tlb_small[0].tag.vpn_tag, delr_mem1.index}, 0);
          				delr_mem2.flush_small[1] <= tlb_flush_match(tlbflush, tlb_small[1].data, tlb_small[1].tag.ctx, {tlb_small[1].tag.vpn_tag, delr_mem1.index}, 0);
          				delr_mem2.flush_large[0] <= tlb_flush_match(tlbflush, tlb_large[0].data, tlb_large[0].tag.ctx, {tlb_large[0].tag.vpn_tag[31:DTLBLARGETAGLSB], delr_mem1.index1, 6'b0}, 1);
          				delr_mem2.flush_large[1] <= tlb_flush_match(tlbflush, tlb_large[1].data, tlb_large[1].tag.ctx, {tlb_large[1].tag.vpn_tag[31:DTLBLARGETAGLSB], delr_mem1.index1, 6'b0}, 1);
				
          				delr_xc <= delr_mem2;
             end
	           
	           //lru ram
             always_ff @(posedge gclk.clk) begin
                r_small_lru <= lru_ram_small[{delr_mem1.tid, delr_mem1.index}];
                r_large_lru <= lru_ram_large[{delr_mem1.tid, delr_mem1.index1}];
          
                //write port
                if (lru_we_small) lru_ram_small[{mem2tlb.tid, delr_xc.index}] <= delr_mem2.lru[0];
                if (lru_we_large) lru_ram_large[{mem2tlb.tid, delr_xc.index1}] <= delr_mem2.lru[1];
              end


            //tlb brams
            dtlbram #(.ECC("TRUE"), .DOREG(DTLBDOREG)) large_way_0(.*,            
                                    												.raddr(tlbram_large_raddr),
                                                .waddr(tlbram_large_waddr),
                                                .we(tlb_large_we[0]),                                                           
                                                .wdata(tlbram_large_din),
                                                .rdata(tlb_large[0]),
                                    												.sberr(tlb_sberr[0]),
                                    												.dberr(tlb_dberr[0]));

            dtlbram #(.ECC("TRUE"), .DOREG(DTLBDOREG))large_way_1(.*,
                                    												.raddr(tlbram_large_raddr),
                                                .waddr(tlbram_large_waddr),
                                                .we(tlb_large_we[1]),                                                           
                                                .wdata(tlbram_large_din),
                                                .rdata(tlb_large[1]),
                                    												.sberr(tlb_sberr[1]),
                                    												.dberr(tlb_dberr[1]));
            
            dtlbram #(.ECC("TRUE"), .DOREG(DTLBDOREG)) small_way_0(.*,
                                    												.raddr(tlbram_small_raddr),
                                                .waddr(tlbram_small_waddr),
                                                .we(tlb_small_we[0]),                                                           
                                                .wdata(tlbram_small_din),
                                                .rdata(tlb_small[0]),
                                    												.sberr(tlb_sberr[2]),
                                    												.dberr(tlb_dberr[2]));

            dtlbram #(.ECC("TRUE"), .DOREG(DTLBDOREG)) small_way_1(.*,
                                    												.raddr(tlbram_small_raddr),
                                                .waddr(tlbram_small_waddr),
                                                .we(tlb_small_we[1]),                                                           
                                                .wdata(tlbram_small_din),
                                                .rdata(tlb_small[1]),
                                    												.sberr(tlb_sberr[3]),
                                    												.dberr(tlb_dberr[3]));
            
endmodule