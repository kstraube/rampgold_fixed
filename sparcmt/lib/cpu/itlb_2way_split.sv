//---------------------------------------------------------------------------   
// File:        itlbram_2way_split.sv
// Author:      Zhangxi Tan
// Description: 2-way set assoc. TLB. Split large and small pages 
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libstd::*;
import libiu::*;
import libmmu::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`endif

module itlbram_2way_split #(parameter int LUTRAMDDR=0) (input iu_clk_type gclk, input bit rst, 
             //input from IU
             input  mmu_iu_itlb_type      iu2tlb,				//@if1
             input  bit [MMUCTXMSB:0]	    ctx,		        //ctx ID @if2
             input  mmu_tlb_flush_probe_type    tlbflush,				//@if2
             //intput from memwalk 
             input  mmu_mmumem_itlb_type  mem2tlb,
             //output to IU
             output mmu_itlb_iu_type      tlbram2iu,
//             output tlb_status_type       tlbstat,
//             output bit                   tlbstat,
             output bit                   sberr,
             output bit                   dberr,
             output bit                   luterr) /* synthesis syn_sharing = "on" */;
			
			mmu_iu_itlb_type	delr_if2;		//if 2
			 
      (* syn_maxfan = 16 *) struct {        
			  bit [NTHREADIDMSB:0]            tid;
			  mmu_page_table_entry_type		pte;		//tlb lookup result
        bit [ITLBINDEXMSB:ITLBINDEXLSB]	index, index1;        
        bit [MMUCTXMSB:0]				           ctx;			//may be shared by some pipe registers in the main pipeline
        bit [31:ITLBTAGLSB]             vpn_tag;           	
        bit [1:0]                       lvl;
			  bit [1:0]						                 lru;
        bit [1:0]					  	               flush_small, flush_large;				
				bit								                tlbram_hit;
				bit                             update_small_lru, update_large_lru;
				bit								                valid;
      }delr_de;   //de
			
			typedef struct packed {
				bit 	valid;					//walk result is valid
				bit		parity;
			}walk_status_type;	
			
			typedef struct packed {
				mmu_page_table_entry_type	pte;
				bit [1:0]     lvl;
				bit							parity;
			}walk_result_type;
			
			(* syn_ramstyle = "select_ram" *) walk_result_type	walk_result[0:NTHREAD-1];	//single read/single write
			(* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]	walk_result_addr;		//TDM address when DDR
			(* syn_maxfan = 16 *) bit					walk_result_we;
			walk_result_type							walk_result_din, r_walk_result;			
			
			(* syn_ramstyle = "select_ram" *) walk_status_type walk_stat[0:NTHREAD-1];	//single read port, two write ports
			bit [NTHREADIDMSB:0] walk_stat_waddr;		
			bit					 walk_stat_we;
			walk_status_type	walk_stat_din, r_walk_stat;			
			
			
			//tlb bram interface signals
      mmu_itlbram_addr_type tlbram_small_raddr, tlbram_small_waddr, tlbram_large_raddr, tlbram_large_waddr;
      mmu_itlbram_data_type tlb_large[0:1], tlb_small[0:1], tlbram_small_din,tlbram_large_din;        
      bit [3:0]      tlb_sberr, tlb_dberr;
			bit [1:0]			   tlb_large_we, tlb_small_we;
             
      bit [1:0]      tlb_large_hit, tlb_small_hit, l1_hit;

      //lru lutram
      (* syn_ramstyle = "select_ram" *)  bit lru_ram_small[0:NTHREAD*NITLBENTRY-1], lru_ram_large[0:NTHREAD*NITLBENTRY-1];   //one read port one write port (use dual port ram for higher performance)			 
      bit                   lru_we_small, lru_we_large;          //write enable
      bit                   r_small_lru, r_large_lru;
			 
			 always_comb begin                                                               
          //tlb bram signals
          tlbram_small_raddr.tid   = iu2tlb.tid;
          tlbram_small_raddr.index = iu2tlb.index;                              
          tlbram_small_waddr.tid   = delr_de.tid;
          tlbram_small_waddr.index = delr_de.index;                
          
          tlbram_large_raddr.tid   = iu2tlb.tid;
          tlbram_large_raddr.index = iu2tlb.index1;                              
          tlbram_large_waddr.tid   = delr_de.tid;
          tlbram_large_waddr.index = delr_de.index1;                

                
          tlbram_small_din.data  	   	 = r_walk_result.pte;
          tlbram_small_din.data.et     = 2;
          tlbram_small_din.tag.vpn_tag = delr_de.vpn_tag;                
				  tlbram_small_din.tag.ctx	 = delr_de.ctx;
				  tlbram_small_din.tag.valid   = ~(|delr_de.flush_small);
				  tlbram_small_din.tag.lvl  = 3;
//          tlbram_small_din.tag.dirty   = '0;			//not used
//				  tlbram_small_din.tag.lru	 = delr_de.lru[0];
				
				  tlbram_large_din 		   = tlbram_small_din;
				  tlbram_large_din.tag.lvl  = r_walk_result.lvl;
				  tlbram_large_din.tag.vpn_tag[ITLBLARGETAGLSB-1: ITLBTAGLSB] = '0;   //no use for large tlb
				  tlbram_large_din.tag.valid =  ~(|delr_de.flush_large);
//				  tlbram_large_din.tag.lru   = delr_de.lru[1];
				
				  tlb_large_we = '0; tlb_small_we = '0;
          if (r_walk_stat.valid & r_walk_result.pte.et == 2) begin
              tlb_small_we[0] = &r_walk_result.lvl & ~delr_de.lru[0] & delr_de.valid;		//only one lru bit is needed 
              tlb_small_we[1] = &r_walk_result.lvl & delr_de.lru[0] & delr_de.valid;

              tlb_large_we[0] = ~(&r_walk_result.lvl) & ~delr_de.lru[1] & delr_de.valid;
              tlb_large_we[1] = ~(&r_walk_result.lvl) & delr_de.lru[1] & delr_de.valid;
          end
          tlb_small_we |= delr_de.flush_small;
				  tlb_large_we |= delr_de.flush_large;                				  
				
          //tlb hit logic
          //tlb_large_hit[0] = (tlb_large[0].tag.vpn_tag == delr_if2.vpn_tag && tlb_large[0].tag.ctx == ctx) ? tlb_large[0].tag.valid : '0;
          //tlb_large_hit[1] = (tlb_large[1].tag.vpn_tag == delr_if2.vpn_tag && tlb_large[1].tag.ctx == ctx) ? tlb_large[1].tag.valid : '0;              
          
          l1_hit[0] = (tlb_large[0].tag.vpn_tag[31:24] == delr_if2.vpn_tag[31:24] && tlb_large[0].tag.ctx == ctx) ? tlb_large[0].tag.valid : '0;
          l1_hit[1] = (tlb_large[1].tag.vpn_tag[31:24] == delr_if2.vpn_tag[31:24] && tlb_large[1].tag.ctx == ctx) ? tlb_large[1].tag.valid : '0;

          unique case (tlb_large[0].tag.lvl)
          0: tlb_large_hit[0] = tlb_large[0].tag.valid;
          1: tlb_large_hit[0] = l1_hit[0]; 
          2: tlb_large_hit[0] = l1_hit[0] & (tlb_large[0].tag.vpn_tag[23:ITLBLARGETAGLSB] == delr_if2.vpn_tag[23:ITLBLARGETAGLSB]);
          default: tlb_large_hit[0] = '0;   //not possible
          endcase

          unique case (tlb_large[1].tag.lvl)
          0: tlb_large_hit[1] = tlb_large[1].tag.valid;
          1: tlb_large_hit[1] = l1_hit[1]; 
          2: tlb_large_hit[1] = l1_hit[1] & (tlb_large[1].tag.vpn_tag[23:ITLBLARGETAGLSB] == delr_if2.vpn_tag[23:ITLBLARGETAGLSB]);
          default: tlb_large_hit[1] = '0;   //not possible
          endcase                    

          tlb_small_hit[0] = (tlb_small[0].tag.vpn_tag == delr_if2.vpn_tag && tlb_small[0].tag.ctx == ctx) ? tlb_small[0].tag.valid : '0;
          tlb_small_hit[1] = (tlb_small[1].tag.vpn_tag == delr_if2.vpn_tag && tlb_small[1].tag.ctx == ctx) ? tlb_small[1].tag.valid : '0;			    
          
          lru_we_small = (|tlb_small_we) | delr_de.update_small_lru;
          lru_we_large = (|tlb_large_we) | delr_de.update_large_lru;
			                    
          //tlb result to IU @ decode stage
                               
				  tlbram2iu.pte = (r_walk_stat.valid) ? r_walk_result.pte : delr_de.pte;
				  tlbram2iu.lvl =  (r_walk_stat.valid) ? r_walk_result.lvl : delr_de.lvl;
          tlbram2iu.valid = (r_walk_stat.valid | delr_de.tlbram_hit); // & delr_de.valid ;		//valid bit will be checked in the immu/icache logic
                
          //ram errors
          sberr = (BRAMPROT) ? |tlb_sberr : '0;
          dberr = (BRAMPROT) ? |tlb_dberr : '0;
          luterr = (LUTRAMPROT) ? ^r_walk_stat | ^r_walk_result: '0;
			 end
			 
       //synthesis translate_off
       covergroup cg_itlb @(posedge gclk.clk);
         tlb_small_hit_0 : coverpoint tlb_small_hit[0] iff (!rst && delr_if2.valid);
         tlb_small_hit_1 : coverpoint tlb_small_hit[1] iff (!rst && delr_if2.valid);
         tlb_large_hit_0 : coverpoint tlb_large_hit[0] iff (!rst && delr_if2.valid);
         tlb_large_hit_1 : coverpoint tlb_large_hit[1] iff (!rst && delr_if2.valid);
         tlb_small_we_0 : coverpoint tlb_small_we[0] iff (!rst);
         tlb_small_we_1 : coverpoint tlb_small_we[1] iff (!rst);
         tlb_large_we_0 : coverpoint tlb_large_we[0] iff (!rst);
         tlb_large_we_1 : coverpoint tlb_large_we[1] iff (!rst);
         tlb_small_write_index : coverpoint tlbram_small_waddr.index iff (!rst && |tlb_small_we);
         tlb_large_write_index : coverpoint tlbram_large_waddr.index iff (!rst && |tlb_large_we);
       endgroup
  
       cg_itlb itlb_stat = new;
      
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
               disable iff (rst || !delr_if2.valid)
                ((|tlb_small_hit && |tlb_large_hit) == 0);
       endproperty
             
       assert property(assert_tlb_large) else $display("@%t found an invalid entry in large_itlb", $time);
       assert property(assert_tlb_small) else $display("@%t found an invalid entry in small_itlb", $time);
       assert property(assert_tlb_hit)  else $display ("@%t both large and small itlb hit", $time);
       
       property assert_tlb_et2;
             @(posedge (gclk.clk)) 
                ((tlb_small_we == 0 || tlbram_small_din.data.et == 2) && (tlb_large_we == 0 || tlbram_large_din.data.et == 2));
       endproperty
       
       assert property(assert_tlb_et2)  else begin $display ("@%t write invalid itlb entries", $time); $stop(0); end
       //synthesis translate_on
			 			 
			 always_ff @(posedge gclk.clk) begin		//pipeline registeres
				delr_if2 <=iu2tlb;        //tid will be shared
                
				delr_de.tid <= delr_if2.tid;
				delr_de.valid <= delr_if2.valid;
				delr_de.index <= delr_if2.index;
				delr_de.index1 <= delr_if2.index1;
        delr_de.ctx <=	ctx;			//may be shared by some pipe registers in the main pipeline
				delr_de.vpn_tag <= delr_if2.vpn_tag;           	
								
				delr_de.lru[0]  <= get_new_2way_lru(tlb_small_hit, {tlb_small[1].tag.valid, tlb_small[0].tag.valid}, r_small_lru);	
        delr_de.lru[1]  <= get_new_2way_lru(tlb_large_hit, {tlb_large[1].tag.valid, tlb_large[0].tag.valid}, r_large_lru);	        
        delr_de.update_small_lru <= (|tlb_small_hit) & delr_if2.valid;
        delr_de.update_large_lru <= (|tlb_large_hit) & delr_if2.valid;
        
        delr_de.flush_small[0] <= tlb_flush_match(tlbflush, tlb_small[0].data, tlb_small[0].tag.ctx, {tlb_small[0].tag.vpn_tag, delr_if2.index}, 0);
        delr_de.flush_small[1] <= tlb_flush_match(tlbflush, tlb_small[1].data, tlb_small[1].tag.ctx, {tlb_small[1].tag.vpn_tag, delr_if2.index}, 0);
        delr_de.flush_large[0] <= tlb_flush_match(tlbflush, tlb_large[0].data, tlb_large[0].tag.ctx, {tlb_large[0].tag.vpn_tag[31:ITLBLARGETAGLSB], delr_if2.index1, 6'b0}, 1);
        delr_de.flush_large[1] <= tlb_flush_match(tlbflush, tlb_large[1].data, tlb_large[1].tag.ctx, {tlb_large[1].tag.vpn_tag[31:ITLBLARGETAGLSB], delr_if2.index1, 6'b0}, 1);								
				
				if (tlb_small_hit[0]) begin
            delr_de.pte <= tlb_small[0].data;
            delr_de.lvl <= 3;
        end
        else if (tlb_small_hit[1]) begin
            delr_de.pte <= tlb_small[1].data;
            delr_de.lvl <= 3;
        end
        else if (tlb_large_hit[0]) begin
            delr_de.pte <= tlb_large[0].data;
            delr_de.lvl <= tlb_large[0].tag.lvl;
        end
        else begin                 
            delr_de.pte <= tlb_large[1].data;
            delr_de.lvl <= tlb_large[1].tag.lvl;
        end
				
				delr_de.tlbram_hit <= |{tlb_small_hit, tlb_large_hit};
			 end
	
	     //lru ram
       always_ff @(posedge gclk.clk) begin
          r_small_lru <= lru_ram_small[{iu2tlb.tid, iu2tlb.index}];
          r_large_lru <= lru_ram_large[{iu2tlb.tid, iu2tlb.index1}];
          
          //write port
          if (lru_we_small) lru_ram_small[{delr_de.tid, delr_de.index}] <= delr_de.lru[0];
          if (lru_we_large) lru_ram_large[{delr_de.tid, delr_de.index1}] <= delr_de.lru[1];
       end
       
		 
			 //walk status ram
			 always_comb begin
				walk_stat_din.valid = (gclk.ce) ? '0 : '1; 
				walk_stat_din.parity = (LUTRAMPROT) ? walk_stat_din.valid : '0;				
				walk_stat_we	= (gclk.ce) ? (delr_if2.valid | rst) : (mem2tlb.op == tlb_refill);         //always clear the walk result 
				
				walk_stat_waddr = (gclk.ce) ? delr_if2.tid : mem2tlb.tid;
			 end
			 
			 //walk result ram
			 always_comb begin	
				walk_result_din.pte = mem2tlb.pte;
				walk_result_din.lvl = mem2tlb.lvl;                               //overload the et to store level information
				walk_result_din.parity = (LUTRAMPROT) ? ^{mem2tlb.pte, mem2tlb.lvl} : '0;
				
				if (LUTRAMDDR) begin
					walk_result_we	 = ~gclk.ce & (mem2tlb.op == tlb_refill);
					walk_result_addr = (gclk.ce) ? delr_if2.tid : mem2tlb.tid;
				end
				else begin
					walk_result_we = (mem2tlb.op == tlb_refill) ? '1 : '0;
					walk_result_addr = mem2tlb.tid;
				end				
			 end
			generate 
				if (LUTRAMDDR) begin
					always_ff @(posedge gclk.clk2x) if (walk_result_we) walk_result[walk_result_addr] <= walk_result_din;
					always_ff @(posedge gclk.clk2x) if (gclk.ce) r_walk_result <= walk_result[walk_result_addr];
				end
				else begin
					always_ff @(posedge gclk.clk) if (walk_result_we) walk_result[walk_result_addr] <= walk_result_din;
					always_ff @(posedge gclk.clk) r_walk_result <= walk_result[delr_if2.tid];
				end
			endgenerate
			
			//walk status ram
			always_ff @(posedge gclk.clk2x) if (walk_stat_we) walk_stat[walk_stat_waddr] <=  walk_stat_din;
			always_ff @(posedge gclk.clk2x) if (gclk.ce) r_walk_stat <= walk_stat[delr_if2.tid];
			
			//tlb brams
            itlbram #(.ECC("TRUE")) large_way_0(.*,            
                                    												.raddr(tlbram_large_raddr),
                                                .waddr(tlbram_large_waddr),
                                                .we(tlb_large_we[0]),                                                           
                                                .wdata(tlbram_large_din),
                                                .rdata(tlb_large[0]),
                                    												.sberr(tlb_sberr[0]),
                                    												.dberr(tlb_dberr[0]));

            itlbram #(.ECC("TRUE"))large_way_1(.*,
                                    												.raddr(tlbram_large_raddr),
                                                .waddr(tlbram_large_waddr),
                                                .we(tlb_large_we[1]),                                                           
                                                .wdata(tlbram_large_din),
                                                .rdata(tlb_large[1]),
                                    												.sberr(tlb_sberr[1]),
                                    												.dberr(tlb_dberr[1]));
            
            itlbram #(.ECC("TRUE")) small_way_0(.*,
                                    												.raddr(tlbram_small_raddr),
                                                .waddr(tlbram_small_waddr),
                                                .we(tlb_small_we[0]),                                                           
                                                .wdata(tlbram_small_din),
                                                .rdata(tlb_small[0]),
                                    												.sberr(tlb_sberr[2]),
                                    												.dberr(tlb_dberr[2]));

            itlbram #(.ECC("TRUE")) small_way_1(.*,
                                    												.raddr(tlbram_small_raddr),
                                                .waddr(tlbram_small_waddr),
                                                .we(tlb_small_we[1]),                                                           
                                                .wdata(tlbram_small_din),
                                                .rdata(tlb_small[1]),
                                    												.sberr(tlb_sberr[3]),
                                    												.dberr(tlb_dberr[3]));
 endmodule 

//The followin module doesn't work
module itlbram_2way_split_fast #(parameter int LUTRAMDDR=1) (input iu_clk_type gclk, input bit rst, 
             //input from IU
             input  mmu_iu_itlb_type      iu2tlb,
             input  bit [MMUCTXMSB:0]	    ctx,		        //ctx ID
             input  mmu_tlb_flush_probe_type    tlbflush,
             //intput from mem (only used for pte refill)
             input  mmu_mmumem_itlb_type  mem2tlb,
             //output to IU
             output mmu_itlb_iu_type      tlbram2iu,
//             output tlb_status_type       tlbstat,
             output bit                   tlbstat,
             output bit                   sberr,
             output bit                   dberr,
             output bit                   luterr);
             
             typedef struct packed {
                bit [1:0]                       nway;          //way selected to update, nway[0] - small, nway[1] - large
                bit [ITLBINDEXMSB:ITLBINDEXLSB]	index;         
                mmu_itlb_tag_type               tag;
                bit                             parity;
             }tlbmem_state_type;

             
             typedef struct packed {
//                tlb_status_type   stat;
                bit               stat;
                bit               parity;
             }tlb_status_ram_type;         
             
             //pipeline registers
             mmu_iu_itlb_type                       r_iu2tlb;
             mmu_mmumem_itlb_type                   r_mem2tlb;
             bit [NTHREADIDMSB:0]                   r_frommem_busy_tid;
             bit                                    r_frommem_busy_we;

             //lutram signals
             (* syn_ramstyle = "select_ram" *)  tlbmem_state_type state_ram[0:NTHREAD-1]; 
             (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]           state_ram_addr;
             tlbmem_state_type                  v_state_ram, r_state_ram;
             
             (* syn_ramstyle = "select_ram" *)  bit lru_ram_small[0:NTHREAD*NITLBENTRY-1], lru_ram_large[0:NTHREAD*NITLBENTRY-1];   //one read port two write ports
             (* syn_maxfan = 16 *) bit [log2x(NTHREAD*NITLBENTRY)-1:0]           lru_ram_waddr, lru_ram_raddr;
             bit                   lru_we_small, lru_we_large;          //write enable
             bit [1:0]             lru_wdata;                           //TDM write data; 
             bit                   tlb_acc_valid;
             
             (* syn_ramstyle = "select_ram" *)  tlb_status_ram_type tlb_stat[0:NTHREAD-1];   //one read port two write ports
              tlb_status_ram_type   stat_wdata, stat_rdata;
              bit                  stat_waddr, stat_we;
              
              
             //tlb bram interface signals
             mmu_itlbram_addr_type fromiu_addr, frommem_addr;
             mmu_itlbram_data_type tlb_large[0:1], tlb_small[0:1], frommem_data, fromiu_data;        
             bit [1:0]             frommem_we_large, frommem_we_small, fromiu_we_large, fromiu_we_small;
             bit [3:0]             tlb_sberr, tlb_dberr;
             
             bit [1:0]             tlb_large_hit, tlb_small_hit;
             bit                   tlb_hit;
             
             always_comb begin
                tlb_hit = |{tlb_small_hit, tlb_large_hit};
                
                //state ram signals
                v_state_ram.tag.vpn_tag = r_iu2tlb.vpn_tag;  
                v_state_ram.index       = r_iu2tlb.index;
                v_state_ram.tag.ctx     = ctx;
                v_state_ram.tag.valid   = 1'b1;     //no used, will be optimized
                
                v_state_ram.nway[0] = get_replaced_2way_lru({tlb_small[1].tag.valid, tlb_small[0].tag.valid},lru_ram_small[lru_ram_raddr]);
                v_state_ram.nway[1] = get_replaced_2way_lru({tlb_large[1].tag.valid, tlb_large[0].tag.valid},lru_ram_large[lru_ram_raddr]);

                v_state_ram.parity = (LUTRAMPROT)? ^{v_state_ram.nway, v_state_ram.tag} : 1'b0;
                
                state_ram_addr = (gclk.ce) ? mem2tlb.tid : r_iu2tlb.tid;        //used for LUTRAM DDR only
                
                //lru ram signals                
                lru_wdata     = (gclk.ce) ? {get_referenced_2way_lru(tlb_large_hit), get_referenced_2way_lru(tlb_small_hit)}  : r_state_ram.nway;
                tlb_acc_valid = r_iu2tlb.valid & (tlbflush.op == flush_probe_none);
                lru_we_small  = (gclk.ce) ? (tlb_acc_valid & (|tlb_small_hit)): (r_mem2tlb.op == tlb_refill) & &r_mem2tlb.lvl;
                lru_we_large  = (gclk.ce) ? (tlb_acc_valid & (|tlb_large_hit)): (r_mem2tlb.op == tlb_refill) & ~(&r_mem2tlb.lvl);
                lru_ram_raddr = {iu2tlb.tid, iu2tlb.index};
                lru_ram_waddr = (gclk.ce) ? lru_ram_raddr : {r_mem2tlb.tid, r_state_ram.index};
                
                
                //status ram signals
                stat_rdata      = tlb_stat[r_iu2tlb.tid];
//                tlbstat         = stat_rdata;
                stat_waddr      = (gclk.ce) ? r_iu2tlb.tid : r_frommem_busy_tid;
                stat_we         = (gclk.ce) ? (~tlb_hit & (tlbflush.op != flush_probe_none) & r_iu2tlb.valid) : r_frommem_busy_we;
                stat_wdata.stat = (~gclk.ce | rst) ? '0 : '1;

/*              
                if (rst) 
                  stat_wdata.stat = tlb_stat_ready;
                else if (gclk.ce) 
                  stat_wdata.stat = (tlbflush.op != flush_none) ? tlb_stat_pending : tlb_stat_busy;
                else
                  stat_wdata.stat = tlb_stat_ready;
*/
                stat_wdata.parity = (LUTRAMPROT)? ^stat_wdata.stat : '0;
                
                //tlb bram signals
                fromiu_addr.tid   = iu2tlb.tid;
                fromiu_addr.index = iu2tlb.index;              
                
                frommem_addr.tid   = r_mem2tlb.tid;
                frommem_addr.index = r_state_ram.index;                
                frommem_data.data  = r_mem2tlb.pte;
                frommem_data.tag   = r_state_ram.tag;                
                
                if (mem2tlb.op == tlb_refill) begin
                  frommem_we_small[0] = &r_mem2tlb.lvl & ~r_state_ram.nway[0];
                  frommem_we_small[1] = &r_mem2tlb.lvl & r_state_ram.nway[0];

                  frommem_we_large[0] = ~(&r_mem2tlb.lvl) & ~r_state_ram.nway[1];
                  frommem_we_large[1] = ~(&r_mem2tlb.lvl) & r_state_ram.nway[1];
                end
                else begin
                  frommem_we_large = '0; frommem_we_small = '0;
                end
                
                //tlb hit logic
                tlb_large_hit[0] = (tlb_large[0].tag.vpn_tag == r_iu2tlb.vpn_tag && tlb_large[0].tag.ctx == ctx) ? tlb_large[0].tag.valid : '0;
                tlb_large_hit[1] = (tlb_large[1].tag.vpn_tag == r_iu2tlb.vpn_tag && tlb_large[1].tag.ctx == ctx) ? tlb_large[1].tag.valid : '0;

                tlb_small_hit[0] = (tlb_small[0].tag.vpn_tag == r_iu2tlb.vpn_tag && tlb_small[0].tag.ctx == ctx) ? tlb_small[0].tag.valid : '0;
                tlb_small_hit[1] = (tlb_small[1].tag.vpn_tag == r_iu2tlb.vpn_tag && tlb_small[1].tag.ctx == ctx) ? tlb_small[1].tag.valid : '0;
                
                //tlb result to IU
                if (tlb_small_hit[0])
                  tlbram2iu.pte = tlb_small[0].data;
                else if (tlb_small_hit[1])
                  tlbram2iu.pte = tlb_small[1].data;
                else if (tlb_large_hit[0])
                  tlbram2iu.pte = tlb_large[0].data;
                else                  
                  tlbram2iu.pte = tlb_large[1].data;
                
                tlbram2iu.valid = tlb_hit;
                
                //flush logic
                fromiu_data = '0;                           //default data
                fromiu_we_large = '0; fromiu_we_small = '0;
                
                fromiu_we_large[0] = tlb_flush_match(tlbflush, tlb_large[0].data, tlb_large[0].tag.ctx, {tlb_large[0].tag.vpn_tag, r_iu2tlb.index}, 1);                
                fromiu_we_large[1] = tlb_flush_match(tlbflush, tlb_large[1].data, tlb_large[1].tag.ctx, {tlb_large[1].tag.vpn_tag, r_iu2tlb.index}, 1);                

                fromiu_we_small[0] = tlb_flush_match(tlbflush, tlb_small[0].data, tlb_small[0].tag.ctx, {tlb_small[0].tag.vpn_tag, r_iu2tlb.index}, 0);                
                fromiu_we_small[1] = tlb_flush_match(tlbflush, tlb_small[1].data, tlb_small[1].tag.ctx, {tlb_small[1].tag.vpn_tag, r_iu2tlb.index}, 0);                
                                
                //ram errors
                sberr = (BRAMPROT) ? |tlb_sberr : '0;
                dberr = (BRAMPROT) ? |tlb_dberr : '0;
                luterr = (LUTRAMPROT) ? ^r_state_ram |  ^stat_rdata : '0;
             end
             
            //state ram
             generate 
              if (LUTRAMDDR) begin
                always_ff @(posedge gclk.clk) state_ram[state_ram_addr] <= v_state_ram;                  //write port
                always_ff @(negedge gclk.clk) r_state_ram <= state_ram[state_ram_addr];                  //read port
              end 
              else begin
                always_ff @(posedge gclk.clk) r_state_ram <= state_ram[mem2tlb.tid];                   //read port
                always_ff @(posedge gclk.clk) state_ram[r_iu2tlb.tid] <= v_state_ram;                  //write port
              end
             endgenerate         
             
             //lru ram
             always_ff @(posedge gclk.clk2x) begin
              if (lru_we_small) lru_ram_small[lru_ram_waddr] <= lru_wdata[0];
              if (lru_we_large) lru_ram_large[lru_ram_waddr] <= lru_wdata[1];
             end
             
             //status ram
             always_ff @(posedge gclk.clk2x) begin
               if (stat_we) tlb_stat[stat_waddr] <= stat_wdata;
               if (gclk.ce) tlbstat <= stat_rdata.stat;                 //MCP here
             end  
                 
             //pipeline registers
             always_ff @(posedge gclk.clk) begin
//                tlbstat  <= stat_rdata.stat;   //registered output 
                
                r_iu2tlb  <= iu2tlb;
                r_mem2tlb <= mem2tlb;

                r_frommem_busy_tid <= r_mem2tlb.tid;
                r_frommem_busy_we  <= (r_mem2tlb.op == tlb_refill);
             end


            //tlb brams
            itlbram_fast #(.ECC("TRUE")) large_way_0(.*,            
                                .fromiu_we(fromiu_we_large[0]),
                                .frommem_we(frommem_we_large[0]),
                                .toiu_data(tlb_large[0]),
                                .sberr(tlb_sberr[0]),
                                .dberr(tlb_dberr[0]));

            itlbram_fast #(.ECC("TRUE"))large_way_1(.*,
                                .fromiu_we(fromiu_we_large[1]),
                                .frommem_we(frommem_we_large[1]),
                                .toiu_data(tlb_large[1]),
                                .sberr(tlb_sberr[1]),
                                .dberr(tlb_dberr[1]));
            
            itlbram_fast #(.ECC("TRUE")) small_way_0(.*,
                                .fromiu_we(fromiu_we_small[0]),            
                                .frommem_we(frommem_we_small[0]),
                                .toiu_data(tlb_small[0]),
                                .sberr(tlb_sberr[2]),
                                .dberr(tlb_dberr[2]));

            itlbram_fast #(.ECC("TRUE")) small_way_1(.*,
                                .fromiu_we(fromiu_we_small[1]),                              
                                .frommem_we(frommem_we_small[1]),
                                .toiu_data(tlb_small[1]),
                                .sberr(tlb_sberr[3]),
                                .dberr(tlb_dberr[3]));
            
endmodule