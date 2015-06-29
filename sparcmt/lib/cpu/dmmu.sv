//---------------------------------------------------------------------------   
// File:        dmmu.v
// Author:      Zhangxi Tan
// Description: dmmu implementation. TLB/address walk. TLB refill is done by HW.
//		Tag, data are mapped to separate BRAMs (RAMB18_36)
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libmmu::*;
import libcache::*;
import libopcodes::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`endif

`include "dumbmmu.sv"


module dmmutlb #(parameter bit LARGEPAGETLB=1'b1, parameter bit LUTRAMDDR = 0 , parameter DTLBDOREG = 1) (input iu_clk_type gclk, input rst, 
             input  mmu_iu_dtlb_type      iu2tlb,              //@EX1
             input  mmu_mmumem_dtlb_type  mem2tlb,             //@XC
             input  mmu_tlb_flush_probe_type    tlbflush,            //@EX2/MEM1
             input  bit                   valid,               //@EX2/MEM1
             input  bit                   dirty,               //@EX2/MEM1
             output mmu_dtlb_iu_type      tlb2iu,              //@EX2/MEM1
             output bit                   replay,              //@EX2/MEM1, dtlb is busy with flushing
            //soft error protection 
             output bit                   sberr,
             output bit                   dberr,
             output bit                   luterr           
            )/* synthesis syn_sharing = "on" */;
        //pipeline register
        bit [NTHREADIDMSB:0]  mem1_tid, ex2_tid;     //can be shared
                
        //flush state - dual port
        typedef struct packed{
          bit [DTLBINDEXMSB:DTLBINDEXLSB]   index;          //working index
          tlb_flush_probe_op_type                 op;
          bit                               parity;
        }dtlb_flush_state_type;
        
        //flush data (can be double clocked)
        typedef struct packed {
          bit [MMUCTXMSB:0]	  ctx;
          bit [31:12]         va;
          bit                 parity;
        }dtlb_flush_data_type;
        
        
        (* syn_ramstyle = "select_ram" *) dtlb_flush_state_type    flush_state[0:NTHREAD-1];  //one read port two write ports
        (* syn_ramstyle = "select_ram" *) dtlb_flush_data_type     flush_data[0:NTHREAD-1];   //one read port one write port
        (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]                 flush_data_addr;           //TDM addr if DDR               
        dtlb_flush_data_type     flush_wdata, flush_rdata;
        dtlb_flush_state_type    flush_wstate, flush_rstate, r_flush_rstate, d_flush_rstate;                                  
        bit                      flush_state_we;
        bit                      flush_data_luterr, flush_state_luterr;
                
        //to dtlb signals
        mmu_tlb_flush_probe_type       dtlbflush;               //flush signals        
        mmu_iu_dtlb_type         iu2tlbram;
        
        bit                      tlbstat;
        bit                      mmumem_en;
        
        
        mmu_dtlb_iu_type         tlbram2iu, v_tlb2iu;
        
        always_comb begin                                                        
                                      
              //tlb->iu
              v_tlb2iu = tlbram2iu;
              v_tlb2iu.pte.et = 2;        //always store valid entries in tlb

              if (r_flush_rstate.op != flush_probe_none) begin
                replay = '1;              //mmu is busy with flush, replay is needed when dtlb has more sets than itlb        
                v_tlb2iu.valid = '0;
              end
              else
                replay = '0;

              tlb2iu =  v_tlb2iu;
              
              

              //flush control logic

              flush_data_addr = (gclk.ce) ? ((DTLBDOREG)? ex2_tid : iu2tlb.tid) : mem1_tid; 
              flush_wdata.va  = tlbflush.va;
              flush_wdata.ctx = tlbflush.ctx;              
              
              flush_wdata.parity = (LUTRAMPROT)? ^{flush_wdata.ctx, flush_wdata.va} : '0;              
              flush_data_luterr = (LUTRAMPROT) ? ^flush_rdata : '0;
              
              
              //flush fsm
              flush_rstate = flush_state[iu2tlb.tid];              
              
              
              //EX2/MEM1 signals                                 
              flush_state_we = '0;                             //default value
              if ((r_flush_rstate.op != flush_probe_none) || rst) begin   //we are doing flush now
                flush_state_we = '1;
                flush_wstate.op = (r_flush_rstate.index == LASTDTLBINDEX || rst) ? flush_probe_none : r_flush_rstate.op;
                flush_wstate.index = r_flush_rstate.index + 1;
              end
              else begin                
                flush_wstate.index =  '0;
                flush_state_we = (tlbflush.op == flush_probe_none) ? '0 : '1;
                flush_wstate.op = tlbflush.op;
              end
              
              flush_wstate.parity = (LUTRAMPROT) ? ^{flush_wstate.index , flush_wstate.op} : '0;
              flush_state_luterr = (LUTRAMPROT) ? ^r_flush_rstate : '0;
              
              //iu->tlbram
              iu2tlbram = iu2tlb;
              if (flush_rstate.op != flush_probe_none) begin 
                iu2tlbram.index   = flush_rstate.index;    //change the index we are reading if doing flush
                iu2tlbram.index1  = flush_rstate.index;
                //Not used until EX2/MEM1
                //iu2tlbram.ctx     = flush_rdata.ctx;        
                //iu2tlbram.vpn_tag = flush_rdata.va[31:DTLBTAGLSB];
              end
              
              //EX2/MEM1
              if (r_flush_rstate.op != flush_probe_none) begin
                dtlbflush.op  = r_flush_rstate.op;
                dtlbflush.ctx = flush_rdata.ctx;
                dtlbflush.va  = flush_rdata.va; 
              end
              else begin
                dtlbflush.op  = tlbflush.op;
                dtlbflush.ctx = tlbflush.ctx;
                dtlbflush.va  = tlbflush.va;                 
              end
              
              //error detection interface
              luterr = flush_data_luterr | flush_state_luterr;
        end        
   
        //pipeline registers   
        always_ff @(posedge gclk.clk) begin 
          if (DTLBDOREG) begin
            ex2_tid <= iu2tlb.tid;
            mem1_tid <= ex2_tid;
          end
          else
            mem1_tid <= iu2tlb.tid;
        end
                        
        //flush data ram
        generate 
          if (LUTRAMDDR) begin
            always_ff @(posedge gclk.clk2x) begin
              if (tlbflush.op !=  flush_probe_none && !gclk.ce)
                flush_data[flush_data_addr] <= flush_wdata;
            end
            always_ff @(posedge gclk.clk2x) if (gclk.ce) flush_rdata <= flush_data[flush_data_addr];
          end
          else begin
            always_ff @(posedge gclk.clk) if (tlbflush.op != flush_probe_none) flush_data[mem1_tid] <= flush_wdata;
            always_ff @(posedge gclk.clk) flush_rdata <= flush_data[(DTLBDOREG)? ex2_tid : iu2tlb.tid];            
          end
        endgenerate
        
        //flush state ram
        always_ff @(posedge gclk.clk) if (flush_state_we) flush_state[mem1_tid] <= flush_wstate;
        always_ff @(posedge gclk.clk) begin 
          if (DTLBDOREG) begin
            d_flush_rstate <= flush_rstate;
            r_flush_rstate <= d_flush_rstate;
          end
          else
            r_flush_rstate <= flush_rstate;
        end
      
          
        generate 
          if (LARGEPAGETLB) begin
            dtlbram_2way_split  #(.DTLBDOREG(DTLBDOREG)) dtlbram_split(.gclk,.rst, 
                                             .iu2tlb(iu2tlbram),
                                             .dirty,
                                             .valid,
                                             .tlbflush(dtlbflush),
                                             .mem2tlb,
                                             .tlbram2iu,                                 
                                             .sberr,
                                             .dberr
                                              );
          end
          else begin    //Todo: implement 4-way set assoc unified TLB

          end
        endgenerate
                                                 
        
endmodule

//output everything at mem1
task automatic decode_mmu_ops(input dmmu_if_iu_in_type iu2dmmu, output mmureg_write_in_type mmureg_write, output mmu_tlb_flush_probe_type  dtlb_flush, output mmureg_op_type read_op, output bit mmu_bypass, output mmu_tlb_flush_probe_type mmu_probe);
	mmureg_write_in_type	v_mmureg_write;
	mmureg_op_type			v_read_op;
	mmu_tlb_flush_probe_type		v_dtlb_flush, v_mmu_probe;

	//default values
	v_read_op = mmureg_nop;
	v_mmureg_write.tid 	= iu2dmmu.m1.tid;
	v_mmureg_write.data = iu2dmmu.m1.mmureg_data;
	v_mmureg_write.op	= mmureg_nop;
	v_mmu_probe = '0;
  
	v_dtlb_flush.op = flush_probe_none;
  v_dtlb_flush.ctx = iu2dmmu.m1.immu_data.ctx_reg;
	v_dtlb_flush.va = iu2dmmu.m1.va[31:12];
	
	v_mmu_probe = v_dtlb_flush;
    
	if (iu2dmmu.m1.valid & iu2dmmu.m1.ldst_a) begin
		if (!iu2dmmu.m1.ldst) begin    //load
			unique case(iu2dmmu.m1.asi)
			ASI_MMUREGS: begin
						 unique case (iu2dmmu.m1.va[11:8])
						 4'd0: v_read_op = mmureg_ctr;
						 4'd1: v_read_op = mmureg_ctx_ptr;
						 4'd2: v_read_op = mmureg_ctx;
						 4'd3: v_read_op = mmureg_fs;
						 4'd4: v_read_op = mmureg_faddr;
						 default:;
						 endcase
						end
			ASI_MMUFLUSHPROBE: begin
                  						unique case(iu2dmmu.m1.va[11:8])
                  						4'd0: v_mmu_probe.op = flush_probe_l3;
                  						4'd1: v_mmu_probe.op = flush_probe_l2;
                  						4'd2: v_mmu_probe.op = flush_probe_l1;
                  						4'd3: v_mmu_probe.op = flush_probe_l0;
                  						4'd4: v_mmu_probe.op = flush_probe_all;
                  						default: ;
                  						endcase
			                 end
			default :;
			endcase
		end
		else begin
			unique case(iu2dmmu.m1.asi)
			ASI_MMUREGS: begin			 
      		  		  if (iu2dmmu.m1.ucmode) begin
          					 unique case (iu2dmmu.m1.va[11:8])
						    4'd0: v_mmureg_write.op = mmureg_ctr;
						    4'd1: v_mmureg_write.op = mmureg_ctx_ptr;
						    4'd2: v_mmureg_write.op = mmureg_ctx;			
						    default:;
						    endcase
						   end
						end
			ASI_MMUFLUSHPROBE: begin 
						unique case(iu2dmmu.m1.va[11:8])
						4'd0: begin v_dtlb_flush.op = flush_probe_l3; v_mmureg_write.op = mmureg_iflush_l3; end
						4'd1: begin v_dtlb_flush.op = flush_probe_l2; v_mmureg_write.op = mmureg_iflush_l2; end
						4'd2: begin v_dtlb_flush.op = flush_probe_l1; v_mmureg_write.op = mmureg_iflush_l1; end
						4'd3: begin v_dtlb_flush.op = flush_probe_l0; v_mmureg_write.op = mmureg_iflush_l0; end
						4'd4: begin v_dtlb_flush.op = flush_probe_all; v_mmureg_write.op = mmureg_iflush_all; end
						default: ;
						endcase
						end
		  default : ; 	//do nothing
		  endcase
  	end
	end
	
	//output
	mmu_bypass = (((((iu2dmmu.m1.asi == ASI_MMU_BP || iu2dmmu.m1.asi == ASI_MMUREGS) && iu2dmmu.m1.ldst_a) || !iu2dmmu.m1.immu_data.ctrl_reg.e) && v_mmu_probe.op == flush_probe_none) ? iu2dmmu.m1.valid : '0) | (MMUEN == 0);
	mmu_probe = v_mmu_probe;
	dtlb_flush = v_dtlb_flush;
	mmureg_write = v_mmureg_write;
	read_op	= v_read_op;
endtask

function bit [31:0] get_probe_result(mmu_page_table_entry_type pte, bit [1:0] current_level, tlb_flush_probe_op_type probe_op);
  bit [31:0]  probe_result;
  
  probe_result = '0;

  unique case (probe_op)
  flush_probe_l3: if (current_level == 3 && (pte.et == 2 ||  pte.et == 0))  probe_result = pte;
  flush_probe_l2: if (current_level == 2 && pte.et != 3) probe_result = pte;
  flush_probe_l1: if (current_level == 1 && pte.et != 3) probe_result = pte;
  flush_probe_l0: if (pte.et !=3 ) probe_result = pte;
  default : if (pte.et == 2) probe_result = pte;
  endcase
  
  return probe_result;
endfunction

module dmmu_if #(parameter DTLBDOREG=1)
     (input iu_clk_type gclk, input rst, 
      input dmmu_if_iu_in_type   iu2dmmu,      //input from IU      
	    output dmmu_iu_out_type 	  dmmu2iu,		    //output to IU	 	       
	    //--------------------interface to mmu-----------------
	    output mmu_mmumem_itlb_type    toitlb,           
     	//--------------------Host $ interface------------------
     	output mmu_host_cache_in_type  mmu2hc,		//@mem1
     	input  mmu_host_cache_out_type hc2mmu,		//@xc
   //  	output dcache_mmu_in_type      mmu2hcfsm, // @XC
	    output bit                     mmu2hc_invalid,
	    //host performance counter
	    output bit                   itlb_miss,
	    output bit                   dtlb_miss,
      //soft error protection 
      output bit                   sberr,
      output bit                   dberr,
      output bit                   luterr           	 
	) /* synthesis syn_sharing = "on" */;		
	
	
	(* syn_maxfan = 16 *) struct {
    bit	[NTHREADIDMSB:0] tid;				//may be shared 
    mmu_page_table_entry_type pte;
    bit                  pte_valid;       //dtlb hit
//	  bit					             fs_we;	  		//update fault status register?
	  bit [31:0]			        va;			  //fault address & page offset
	  bit                  dmmu_replay;
    //bit [11:2]           page_offset;     //to output paddr at @xc
    bit                  itlbmiss;
    bit                  exception_valid;
    bit [2:0]            mmuat;
    bit [1:0]            walk_level;
		tlb_flush_probe_op_type       probe_op;
		mmureg_write_in_type mmureg_write;
		bit [31:0]           mmureg_read;
		bit                  mmureg_read_valid;
	//immu fault data
    bit [9:8]   immu_l;          //level
	  bit [7:5]   immu_at;         //access type
	  bit [4:2]   immu_ft;         //fault type
	  bit         iaex;            //i-exception
	  bit         fs_clr;
	  bit         nf;
	}delr_m2, delr_xc;
	
  mmu_page_table_entry_type   new_pte;

	bit                         tlb_valid;

  //mmu register read signals
  mmu_control_register_type	        mmureg_read_ctr;
  mmu_fault_status_register_type    mmureg_read_fs;
  
  
	bit [31:0]                   mmureg_read;
	
	//mmu->hc
	bit                          mmu2hc_nop;

  //tlbram signals
  //mmu_iu_dtlb_type		            iu2tlb;		
  mmu_tlb_flush_probe_type      tlbflush;
  mmu_mmumem_dtlb_type          mem2tlb;             //@XC
	mmu_dtlb_iu_type 	            tlb2iu; 
	bit                           tlbmiss;
	bit                           dtlb_replay;
	bit                           dtlb_luterr;
  
  //walk signals
  mmu_dtlb_mmumem_type                      dtlb2walk;  
  mmu_context_table_ptr_register_ram_type   mmureg_ctx_ptr_dout;
  mmu_host_cache_in_type                    walk2hc;
  mmu_host_cache_out_type                   hc2walk;	//@XC only
  bit [1:0]                                 current_level, next_level;
  bit                                       walk_luterr;
  bit                                       walk_finished;

  //mmu lda/sta decode signals
  mmureg_write_in_type mmureg_write; 
  mmureg_op_type read_op; 
  bit mmu_bypass; 
  mmu_tlb_flush_probe_type  mmu_probe;
  
  //mmu exception signals
  bit [2:0]         mmuat;
  bit [2:0]         mmuft;        
  bit               exception;   //exception
  
  //mmu probe signals
  bit [31:0]        probe_result;
  
  //fault address register signals
  mmu_fault_address_register_ram_type     faddr_din, faddr_dout;
  bit                                     faddr_we;  
  bit									  mmu_faddr_luterr;
  
  //fault status register signals
  mmu_fault_status_register_ram_type      fs_din, fs_dout;
  bit                                     fs_we;  
  bit                                     fs_clr;

  mmu_iu_dtlb_type fromitlb;
  //pipeline register (can be retimed, used when DTLBDOREG=1)
  always_ff @(posedge gclk.clk)  fromitlb <= iu2dmmu.ex1.iu2dtlb;
  
  always_comb begin        
//    fromitlb.tid = iu2dmmu.ex1.iu2dtlb.tid;
//    fromitlb.ctx = iu2dmmu.ex1.iu2dtlb.ctx;
    
    dtlb2walk.tid = iu2dmmu.m1.tid;
    dtlb2walk.addr = iu2dmmu.m1.va[31:2];
    dtlb2walk.write = iu2dmmu.m1.ldst;
    
    decode_mmu_ops(iu2dmmu, mmureg_write, tlbflush, read_op, mmu_bypass, mmu_probe);    
    
    //this mux will be/should be retimed during synthesis
    mmureg_read ='0;mmureg_read_ctr = '0; mmureg_read_fs = '0;
    
    mmureg_read_ctr.e = iu2dmmu.m1.immu_data.ctrl_reg.e; mmureg_read_ctr.nf = iu2dmmu.m1.immu_data.ctrl_reg.nf;
    mmureg_read_fs.l = fs_dout.l; mmureg_read_fs.at = fs_dout.at; mmureg_read_fs.ft = fs_dout.ft; mmureg_read_fs.fav = fs_dout.fav;
    
    fs_clr = '0;  
    unique case(read_op) 
    mmureg_ctx_ptr: mmureg_read[27:2] = mmureg_ctx_ptr_dout.pt;
    mmureg_ctx: mmureg_read[MMUCTXMSB:0] = iu2dmmu.m1.immu_data.ctx_reg;
    mmureg_ctr: mmureg_read = mmureg_read_ctr[31:0];
    mmureg_fs: begin mmureg_read = mmureg_read_fs[31:0]; fs_clr = '1; end
    default:  mmureg_read =  faddr_dout.addr;
    endcase
    
	  
	  //to host $ @ EX2/MEM1
	  mmu2hc.tid = walk2hc.tid;
	  if (iu2dmmu.m1.immu_data.tlbmiss)
	    mmu2hc.walk_state = tlbmem_read_miss;
	  else if (mmu_bypass | ~iu2dmmu.m1.valid |  (mmu_probe.op == flush_probe_none && tlb2iu.valid) | (tlbflush.op != flush_probe_none))
	    mmu2hc.walk_state = tlbmem_nop;
	  else 
      mmu2hc.walk_state = (!iu2dmmu.m1.ldst) ? ((mmu_probe.op == flush_probe_l3 || mmu_probe.op == flush_probe_l2 || mmu_probe.op == flush_probe_l1) ? tlbmem_noupdate : tlbmem_read_miss ): tlbmem_write_miss;
	  	    

	  new_pte = tlb2iu.pte;
    if (mmu_bypass) new_pte.ppn[27:8] = iu2dmmu.m1.va[31:12];
    else new_pte.ppn[27:8] = get_new_ppn(tlb2iu.pte, tlb2iu.lvl, iu2dmmu.m1.va[31:12]);
    
    //mmu2hc.addr = (mmu_bypass | ~iu2dmmu.m1.valid) ? iu2dmmu.m1.va[31:2] : ((tlb2iu.valid & (mmu_probe == flush_probe_none)) ? {new_pte.ppn[27:8], iu2dmmu.m1.va[11:2]} : walk2hc.addr);	  
    mmu2hc.addr = (!mmu_bypass && (mmu_probe.op != flush_probe_none || !tlb2iu.valid || iu2dmmu.m1.immu_data.tlbmiss)) ? walk2hc.addr : {new_pte.ppn[27:8], iu2dmmu.m1.va[11:2]};	  
    
	  tlb_valid = iu2dmmu.m1.immu_data.ctrl_reg.e & iu2dmmu.m1.valid & (mmu_probe.op == flush_probe_none) & ~mmu_bypass & (tlbflush.op == flush_probe_none);
	  
	  //d-mmu exception detection (can/should be retimed)
    if (iu2dmmu.m1.ldst_a) begin //lda?
        unique case(iu2dmmu.m1.asi)
        8:  mmuat = (!iu2dmmu.m1.ldst) ? MMU_AT_LOADEXE_FROM_USER_INST : MMU_AT_STORE_TO_USER_INST;
        9:  mmuat = (!iu2dmmu.m1.ldst) ? MMU_AT_LOADEXE_FROM_KERNEL_INST : MMU_AT_STORE_TO_KERNEL_INST;
        10: mmuat = (!iu2dmmu.m1.ldst) ? MMU_AT_LOAD_FROM_USER_DATA : MMU_AT_STORE_TO_USER_DATA;
        default: mmuat = (!iu2dmmu.m1.ldst)? MMU_AT_LOAD_FROM_KERNEL_DATA : MMU_AT_STORE_TO_KERNEL_DATA;    //asi = 11
        endcase
       end
    else 
      mmuat = (iu2dmmu.m1.su) ? ((!iu2dmmu.m1.ldst) ? MMU_AT_LOAD_FROM_KERNEL_DATA : MMU_AT_STORE_TO_KERNEL_DATA): ((!iu2dmmu.m1.ldst) ? MMU_AT_LOAD_FROM_USER_DATA : MMU_AT_STORE_TO_USER_DATA);
    
    //detect fault @ XC
    mmuft = detect_mmu_fault(delr_xc.mmuat, (delr_xc.pte_valid) ? delr_xc.pte : hc2mmu.data);
    //exception = (iu2dmmu.m1.immu_data.ctrl_reg.e & ~iu2dmmu.m1.immu_data.ctrl_reg.nf) & (mmuft != MMU_FT_NONE)) ? '1 : '0;    

    unique case (delr_xc.probe_op)
      flush_probe_l3, flush_probe_all: walk_finished = hc2mmu.valid & (hc2mmu.data[1:0] != 1 || delr_xc.walk_level == 3);
      flush_probe_l2: walk_finished = hc2mmu.valid & (hc2mmu.data[1:0] != 1 || delr_xc.walk_level == 2);   
      flush_probe_l1: walk_finished = hc2mmu.valid & (hc2mmu.data[1:0] != 1 || delr_xc.walk_level == 1);   
      flush_probe_l0: walk_finished = hc2mmu.valid;
      default : walk_finished = delr_xc.pte_valid | (hc2mmu.valid & (hc2mmu.data[1:0] != 1 || delr_xc.walk_level == 3));   //l0, or no probe
    endcase
    
//    new_fault = walk_finished & (mmuft != MMU_FT_NONE);    
//    exception = delr_xc.exception_valid & new_fault;
    exception = delr_xc.exception_valid & walk_finished & (mmuft != MMU_FT_NONE);    
    
    //host $ ->mmuwalk interface @XC
    hc2walk = hc2mmu;   //default
    hc2walk.isI = delr_xc.itlbmiss;
    next_level = (walk_finished) ? '0 : delr_xc.walk_level + 1;
    if (walk_finished) hc2walk.walk_state = tlbmem_nop;

    //host performance counters
    itlb_miss = '0;
    dtlb_miss = '0;
    
    if (delr_xc.walk_level == 0) begin
      itlb_miss = delr_xc.itlbmiss & hc2mmu.valid;
      dtlb_miss = ~delr_xc.itlbmiss & hc2mmu.valid;   //probes are counted as dtlb misses
    end

	  if (delr_xc.iaex) begin
		  fs_din.l = delr_xc.immu_l;          //level
		  fs_din.at = delr_xc.immu_at;         //access type
		  fs_din.ft = delr_xc.immu_ft;		//fault type
		  fs_din.fav = '0;        //we don't keep fault address for itlb exceptions
		  fs_we    = '1;		
	  end
	  else begin
      fs_din = '0;
      if (!delr_xc.fs_clr) begin
    		  fs_din.l = delr_xc.walk_level;
		    fs_din.at = delr_xc.mmuat;
    		  fs_din.ft = mmuft;
		    fs_din.fav =  '1;
		  end
		  //fs_we    = (delr_xc.fs_we & new_fault) | delr_xc.fs_clr;
		  fs_we    = exception | delr_xc.fs_clr;
	  end
  	 fs_din.parity = (LUTRAMPROT) ? ^{fs_din.l, fs_din.at, fs_din.ft, fs_din.fav} : '0;
	
	  faddr_din.addr = delr_xc.va;
	  faddr_din.parity = (LUTRAMPROT) ? ^faddr_din.addr : '0;
	  faddr_we = fs_we & ~delr_xc.fs_clr;
	
    //probe result
    probe_result = get_probe_result(hc2mmu.data, delr_xc.walk_level, delr_xc.probe_op);

    //Invalid host $ xaction.
    mmu2hc_nop = exception & delr_xc.pte_valid;
  
    //output to iu
    dmmu2iu.mmureg_read = (delr_xc.probe_op != flush_probe_none) ? probe_result : delr_xc.mmureg_read;
    dmmu2iu.mmureg_valid = delr_xc.mmureg_read_valid | ((delr_xc.probe_op != flush_probe_none) & walk_finished);
    dmmu2iu.paddr = {delr_xc.pte.ppn[27:8], delr_xc.va[11:0]};     //if swap/store can continue always tlb hit without exceptions
    dmmu2iu.exception = exception & ~delr_xc.nf; 
//    dmmu2iu.replay = (delr_xc.probe_op != flush_probe_none) ? ~walk_finished : (~delr_xc.pte_valid | delr_xc.dmmu_replay) & delr_xc.fs_we & ~exception;
    dmmu2iu.replay = (delr_xc.probe_op != flush_probe_none) ? ~walk_finished : (~delr_xc.pte_valid | delr_xc.dmmu_replay) & delr_xc.exception_valid & ~exception;
    dmmu2iu.store_nop =  mmu2hc_nop;

    //output to d$ fsm
    mmu2hc_invalid = mmu2hc_nop;
    //mmu2hcfsm.paddr = delr_xc.va[31:DTLBINDEXLSB];			   //no use	
	  //mmu2hcfsm.tlb_hit = '1;	                            //no use
	  //mmu2hcfsm.valid = ~delr_xc.dmmu_replay;	  	         //are we busy with dtlb flush?
	  //mmu2hcfsm.exception = exception;		                  //no use
  end
  
  //synthesis translate_off
  always_ff @(posedge gclk.clk) begin
      if (iu2dmmu.m1.immu_data.tlbmiss)
          $display("%t: itlb is trying to do a walk from thread %d", $time, iu2dmmu.m1.tid);
      else begin
        if (mmu2hc.walk_state != tlbmem_nop) 
          $display("%t: dtlb is trying to do a walk from thread %d", $time, iu2dmmu.m1.tid);
      end
  end
  //synthesis translate_on
  
  //pipeline registers
  always_ff @(posedge gclk.clk) begin
    //M2
	  delr_m2.tid <= iu2dmmu.m1.tid;
	  delr_m2.va <= iu2dmmu.m1.va;
    delr_m2.pte <= new_pte;
    delr_m2.pte_valid <= tlb2iu.valid & ~iu2dmmu.m1.immu_data.tlbmiss;       //dtlb hit
//	  delr_m2.fs_we <= iu2dmmu.m1.valid & ~mmu_bypass;
	  delr_m2.fs_clr <= fs_clr;
	  delr_m2.dmmu_replay <= dtlb_replay;
    //delr_m2.exception_valid <= iu2dmmu.m1.immu_data.ctrl_reg.e & ~iu2dmmu.m1.immu_data.ctrl_reg.nf & iu2dmmu.m1.valid & (mmu_probe.op == flush_probe_none) & ~mmu_bypass;
    delr_m2.exception_valid <= tlb_valid; 
    delr_m2.nf    <= iu2dmmu.m1.immu_data.ctrl_reg.nf;
    delr_m2.mmuat <= mmuat;
		delr_m2.mmureg_write <= mmureg_write;
		delr_m2.probe_op <= mmu_probe.op;
		delr_m2.mmureg_read <= mmureg_read;
	//	delr_m2.page_offset <= iu2dmmu.m1.va[11:2];
    delr_m2.mmureg_read_valid <= (read_op != mmureg_nop) ? '1 : '0;
    delr_m2.walk_level <= current_level;
    delr_m2.itlbmiss <= iu2dmmu.m1.immu_data.tlbmiss;	
	  delr_m2.immu_l <= iu2dmmu.m1.immu_data.l;          
	  delr_m2.immu_at <= iu2dmmu.m1.immu_data.at;        
	  delr_m2.immu_ft <= iu2dmmu.m1.immu_data.ft;         //fault type
	  delr_m2.iaex    <= iu2dmmu.m1.immu_data.exception;
    //XC
    delr_xc <= delr_m2;
  end
  
  generate 
      if (MMUEN) begin
        dmmutlb #(.LARGEPAGETLB(1'b1), .DTLBDOREG(DTLBDOREG)) gen_dmmutlb(
        .*,
        .valid(tlb_valid),
        .iu2tlb(iu2dmmu.ex1.iu2dtlb),
        .replay(dtlb_replay), 
        .dirty(iu2dmmu.m1.ldst),
        .sberr(sberr), 
        .dberr(dberr), 
        .luterr(dtlb_luterr)
        );	
        
        mmuwalk gen_mmuwalk(.*,
              //tlb interface
              .fromitlb((DTLBDOREG) ? fromitlb : iu2dmmu.ex1.iu2dtlb),
              .fromdtlb(dtlb2walk),
              .toitlb,
              .todtlb(mem2tlb),
              .stop_walk(walk_finished),
              //mmureg write
              .mmureg_in(delr_xc.mmureg_write),
              .mmureg_ctx_ptr_dout,
              //walk <-> host $ interface
              .fromhc(hc2walk),
              .tohc(walk2hc),
              .luterr(walk_luterr)              
              );              
	                
		mmu_fault_status_register	gen_fs_reg(.*,
                                .din(fs_din),
                                .we(fs_we),
                                .rtid((DTLBDOREG) ? fromitlb.tid : iu2dmmu.ex1.iu2dtlb.tid),
                                .wtid(delr_xc.tid),
                                .dout(fs_dout),
		                      						.luterr(mmu_fs_luterr));
		
		mmu_fault_address_register	gen_faddr_reg(.*, 
									.din(faddr_din),
									.we(faddr_we),
									.rtid((DTLBDOREG) ? fromitlb.tid : iu2dmmu.ex1.iu2dtlb.tid),
									.wtid(delr_xc.tid),
									.dout(faddr_dout),
									.luterr(mmu_faddr_luterr));
									
        assign luterr = dtlb_luterr | walk_luterr | mmu_fs_luterr | mmu_faddr_luterr;
      end
      else begin
        assign sberr  = '0;
      		assign dberr  = '0;
  	 	 	 assign luterr = '0;
      end
	endgenerate	
		
endmodule


//------------------------old d-mmu------------------------------------------

module dmmu #(parameter DUMMYMMU = 0) (input iu_clk_type gclk, input rst, 
	    //-------------------------IU interface--------------------
	    input  dmmu_iu_in_type	    iu2dmmu,		    //input from IU 
	    output dmmu_iu_out_type 	  dmmu2iu,		    //output to IU
	    //-------------------------TLB interface-------------------
	    //dtlb <-> IU/MMU interface
	    output tlb_in_type		       iu2dtlb,		    //iu interface
	    input  tlb_out_type 	      dtlb2iu, 
	    //dtlb <-> mem interface
	    input  tlb_in_type		       mem2dtlb,		   //mem interface (mmu walk)
	    output tlb_out_type 	      dtlb2mem,		   //tlb mem interface
	    //--------------------mmu -> dcache inteface----------------
	    output dcache_mmu_in_type 	dmmu2cache, 		//icache input at DE stage 
	    output tlb_error_type	     parity_error		//to monitor circuit
	);		
	
	//--------------pipeline registers--------------			
	typedef struct {				
		bit				             exception;	           //generate exception in 2nd mem
		bit				             valid;		              //lookup is valid
		bit [31:0]		         paddr;		              //physical address		 	
	}delr_exc_type;		//ex pipeline register type
		
	delr_exc_type		delr_x;	
	
  bit [31:0]		         paddr;		     //physical address				

  bit [31:0]           compare_seg; //dummy compare segment
  bit                  exception;   //exception

	assign dmmu2cache.paddr = delr_x.paddr[31:DTLBINDEXLSB];	
	assign dmmu2iu.paddr    = delr_x.paddr;		    //used for microcode of STD

	generate
		if (MMUEN==0) begin	//mmu is disabled
			assign dmmu2cache.tlb_hit       = '1;			       //run & !annul & !ucmode						
//			assign dmmu2cache.rtype         = DMMU_WALK;			  //don't care	
			assign dmmu2cache.exception     = '0;
			assign dmmu2cache.valid         = delr_x.valid;
			assign dmmu2iu.exception        = '0;				
			assign dmmu2iu.parity_error     = '0;	
			assign parity_error.tag_parity  = '0;
			assign parity_error.data_parity = '0;
		end	
		else if (DUMMYMMU) begin
			assign dmmu2cache.tlb_hit       = '1;			       //run & !annul & !ucmode						
//			assign dmmu2cache.rtype         = DMMU_WALK;			  //don't care	
			assign dmmu2cache.exception     = delr_x.exception;
			assign dmmu2cache.valid         = delr_x.valid;
			assign dmmu2iu.exception        = delr_x.exception;				
			assign dmmu2iu.parity_error     = '0;	
			assign parity_error.tag_parity  = '0;
			assign parity_error.data_parity = '0;
		end
	endgenerate	
	
	always_comb begin
		//first cycle read, second cycle write
		iu2dtlb.read.index.D <= iu2dmmu.m1.va[DTLBINDEXMSB:DTLBINDEXLSB];
		iu2dtlb.read.tid     <= iu2dmmu.m1.tid;
		
		//dummy MMU translation
    if (DUMMYMMU) begin
      exception = '0;
      compare_seg = MMU_COMPARE_MASK & iu2dmmu.m2.va;  

      if (compare_seg >= USER_STACK_VIRTUAL_START && compare_seg < KERNEL_VIRTUAL_START)   //user stack
         paddr =  iu2dmmu.m2.va & USER_OFFSET_MASK | USER_STACK_PHYSICAL_START; 
      else if (compare_seg >= KERNEL_VIRTUAL_START)  begin                                 //kernel 
         paddr =  iu2dmmu.m2.va & KERNEL_OFFSET_MASK | KERNEL_PHYSICAL_START; 
         exception =~iu2dmmu.m2.su;        
      end
      else begin
         paddr = iu2dmmu.m2.va;
      end
    end  

	end
	
	always_ff @(posedge gclk.clk) begin				
		
		delr_x.valid <= iu2dmmu.m2.valid; 		
		
		if (MMUEN == 0) begin
			delr_x.paddr     <= iu2dmmu.m2.va;						
			delr_x.exception <= '0;
		end
		else if (DUMMYMMU) begin
			delr_x.paddr     <= paddr;		
			delr_x.exception <= exception;
		end
		else begin   //Todo: replace with real mmu implementation
      delr_x.paddr     <= iu2dmmu.m2.va;						
      delr_x.exception <= '0;
		end
	end
endmodule