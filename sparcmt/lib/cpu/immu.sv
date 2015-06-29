//---------------------------------------------------------------------------   
// File:        immu.sv
// Author:      Zhangxi Tan
// Description: immu implementation. TLB interface, flush logic
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libmmu::*;
import libcache::*;
import libstd::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`endif

`include "dumbmmu.sv"

module immutlb #(parameter bit LARGEPAGETLB=1'b1, parameter int LUTRAMDDR=0) (input iu_clk_type gclk, input rst, 
             input  mmu_iu_itlb_type      iu2tlb,
             input  mmu_mmumem_itlb_type  mem2tlb,
             output mmu_itlb_iu_type      tlb2iu,
             output bit                   tlbmiss,             //need a tlb lookup
             output bit                   replay,
             output mmu_control_register_ram_type immu_ctrl_reg,
             output mmu_context_register_ram_type immu_ctx_reg,
            //soft error protection 
             output bit                   sberr,
             output bit                   dberr,
             output bit                   luterr           
            ) /* synthesis syn_sharing = "on" */;

        
        mmu_iu_itlb_type  delr1_iu2tlb, delr2_iu2tlb;       //internal pipeline registers        

        mmu_itlb_iu_type  tlbram2iu, /*r_tlbram2iu,*/ v_tlb2iu;
        bit               tlbram_luterr;    
        
        mmu_iu_itlb_type  iu2tlbram;
                
        //mmu register control
        mmu_control_register_ram_type ctrl_reg, r_ctrl_reg, new_ctrl_reg;
        mmu_context_register_ram_type ctx_reg, r_ctx_reg, new_ctx_reg;
        bit               ctrl_reg_we, ctx_reg_we;
        bit               ctrl_luterr, ctx_luterr;
    
        //flush state
        typedef struct packed{
          bit [ITLBINDEXMSB:ITLBINDEXLSB]   index;          //working index
          tlb_flush_probe_op_type           op;
          bit                               parity;
        }itlb_flush_state_type;
        
        //flush data
        typedef struct packed {
//          bit [MMUCTXMSB:0]	  ctx;
          bit [31:12]         va;
          bit                 parity;
        }itlb_flush_data_type;
        
        
        (* syn_ramstyle = "select_ram" *) itlb_flush_state_type    flush_state[0:NTHREAD-1];  //one read port two write ports
        (* syn_ramstyle = "select_ram" *) itlb_flush_data_type       flush_data[0:NTHREAD-1];   //one read port one write port
        (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]                 flush_data_addr, flush_state_waddr;           //TDM addr                
        itlb_flush_data_type       flush_wdata, flush_rdata;
        itlb_flush_state_type    flush_wstate, flush_rstate, flush_state_if1;                                  
        bit                      flush_state_we;
        bit                      flush_data_luterr, flush_state_luterr;
        
        mmu_tlb_flush_probe_type       flush2tlbram;
        
        bit                      r_flush_op;
        
        bit                      mmumem_en;
        
        always_comb begin                                                        
                                      
              //tlb->iu
              //v_tlb2iu = r_tlbram2iu;
              v_tlb2iu = tlbram2iu;
              if (!r_ctrl_reg.e) begin 
                v_tlb2iu.valid = delr2_iu2tlb.valid;
                v_tlb2iu.pte.ppn = unsigned'({delr2_iu2tlb.vpn_tag, delr2_iu2tlb.index});     //no translation   
              end

              if (r_flush_op) begin 
                v_tlb2iu.valid = '0;  //mmu is busy with flush
                replay = delr2_iu2tlb.valid;
              end
              else 
                replay = '0;
              
              tlbmiss = delr2_iu2tlb.valid &  ~v_tlb2iu.valid;
              
              tlb2iu         = v_tlb2iu;
              immu_ctrl_reg  = r_ctrl_reg;
              immu_ctx_reg   = r_ctx_reg;
                                               
              //mmu register interface        
              ctrl_reg_we = (rst == 1'b1 || mem2tlb.op == update_ctrl_reg)? '1 :'0;
              ctx_reg_we  = (mem2tlb.op == update_ctx_reg)? '1 :'0;
              
              new_ctrl_reg = (LUTRAMPROT) ? {^mem2tlb.mmureg[1:0],mem2tlb.mmureg[1:0]} : {1'b0, mem2tlb.mmureg[1:0]};                            
              new_ctx_reg  = (LUTRAMPROT) ? {^mem2tlb.mmureg[MMUCTXMSB:0],mem2tlb.mmureg[MMUCTXMSB:0]} : {1'b0, mem2tlb.mmureg[MMUCTXMSB:0]};

              //flush control logic
              flush_data_addr = (LUTRAMDDR) ? ((gclk.ce) ? iu2tlb.tid : mem2tlb.tid) : mem2tlb.tid; 
              flush_wdata.va  = mem2tlb.mmureg[31:12];
  //            flush_wdata.ctx = mem2tlb.mmureg[MMUCTXMSB:0];              
              
              flush_wdata.parity = (LUTRAMPROT)? ^{/*flush_wdata.ctx,*/ flush_wdata.va} : '0;              
              flush_data_luterr = (LUTRAMPROT) ? ^flush_rdata : '0;
              
              //flush fsm
              if (gclk.ce) begin      //MCP here
                flush_state_we  = (flush_rstate.op != flush_probe_none || rst) ? '1 : '0;                
                flush_wstate.op = (flush_rstate.op == flush_probe_l3 || flush_rstate.index == LASTITLBINDEX || rst) ? flush_probe_none : flush_rstate.op;
                flush_wstate.index = flush_rstate.index + 1;  //inc the flush index 
                flush_state_waddr = delr1_iu2tlb.tid;
              end
              else begin                
                flush_wstate.index =  '0;
                flush_state_we = '1;
                unique case(mem2tlb.op)     //assume we have <64 tlbs per-thread
                tlb_flush_l3: begin flush_wstate.op = flush_probe_l3; flush_wstate.index = mem2tlb.mmureg[ITLBINDEXMSB:ITLBINDEXLSB]; end
                tlb_flush_l2: flush_wstate.op = flush_probe_l2;
                tlb_flush_l1: flush_wstate.op = flush_probe_l1;
                tlb_flush_l0: flush_wstate.op = flush_probe_l0; 
                tlb_flush_all: flush_wstate.op = flush_probe_all;
                default: begin flush_wstate.op = flush_probe_none; flush_state_we = '0; end
                endcase
                flush_state_waddr = mem2tlb.tid;                              
              end
              
              flush_wstate.parity = (LUTRAMPROT) ? ^{flush_wstate.index , flush_wstate.op} : '0;
              flush_state_luterr = (LUTRAMPROT) ? ^flush_rstate : '0;
              
              //iu->tlbram
              flush2tlbram = {flush_rstate.op, /*flush_rdata.ctx*/ ctx_reg.ctx, flush_rdata.va};
              iu2tlbram    = iu2tlb;
              flush_state_if1 = flush_state[iu2tlb.tid];
              
              if (flush_state_if1.op != flush_probe_none) begin
                iu2tlbram.index = flush_state_if1.index;
                iu2tlbram.index1 = flush_state_if1.index;
              end
                    
              //error detection interface          
              luterr = ctrl_luterr | ctx_luterr | tlbram_luterr | flush_data_luterr | flush_state_luterr;
        end
        
   
        //pipeline registers   
        always_ff @(posedge gclk.clk) begin
          delr1_iu2tlb <= iu2tlb;
          delr2_iu2tlb <= delr1_iu2tlb;
          
          r_ctrl_reg <= ctrl_reg;
          r_ctx_reg  <= ctx_reg;
          
//          r_tlbram2iu <= tlbram2iu;
          r_flush_op <= (flush_rstate.op != flush_probe_none) ? '1 : '0;
        end   
                
        
        //we need a tlb lookup
        //assign tlbmiss = delr2_iu2tlb.valid & mmumem_en & ~r_tlbram2iu.valid; 
        
        //flush data ram
		generate
    		if (LUTRAMDDR) begin
		    always_ff @(posedge gclk.clk2x) begin
           if (~gclk.ce) begin
          			if (mem2tlb.op == tlb_flush_all || mem2tlb.op == tlb_flush_l0 || mem2tlb.op == tlb_flush_l1 || mem2tlb.op == tlb_flush_l2 || mem2tlb.op == tlb_flush_l3)
            				flush_data[flush_data_addr] <= flush_wdata;
		       end
		    end
		    always_ff @(posedge gclk.clk2x) if (gclk.ce) flush_rdata <= flush_data[flush_data_addr];
    		end
    		else begin
			always_ff @(posedge gclk.clk) 
				if (mem2tlb.op == tlb_flush_all || mem2tlb.op == tlb_flush_l0 || mem2tlb.op == tlb_flush_l1 || mem2tlb.op == tlb_flush_l2 || mem2tlb.op == tlb_flush_l3)
					flush_data[flush_data_addr] <= flush_wdata;
			
			always_ff @(posedge gclk.clk) flush_rdata <= flush_data[iu2tlb.tid];
		 end  
		endgenerate     
        
        //flush state ram
        always_ff @(posedge gclk.clk2x) if (flush_state_we) flush_state[flush_state_waddr] <= flush_wstate;
        always_ff @(posedge gclk.clk2x) if (gclk.ce) flush_rstate <= flush_state_if1;
          
        generate 
          if (LARGEPAGETLB) begin
            itlbram_2way_split itlbram_split(.gclk,.rst, 
                                             .iu2tlb(iu2tlbram),
                                             .ctx(ctx_reg.ctx),		        //ctx ID
                                             .tlbflush(flush2tlbram),
                                             .mem2tlb,
                                             .tlbram2iu,                                             
                                             .sberr,
                                             .dberr,
                                             .luterr(tlbram_luterr));
          end
          else begin    //Todo: implement 4-way set assoc unified TLB

          end
        endgenerate
        
        //instantiate control and context register
        mmu_control_register    gen_ctrl_reg(.gclk, 
                                         .din(new_ctrl_reg),
                                         .we(ctrl_reg_we),
                                         .wtid(mem2tlb.tid),
                                         .rtid(iu2tlb.tid),
                                         .dout(ctrl_reg), 
                                         .luterr(ctrl_luterr));

        mmu_context_register    gen_ctx_reg(.gclk, 
                                         .din(new_ctx_reg),
                                         .we(ctx_reg_we),
                                         .wtid(mem2tlb.tid),
                                         .rtid(iu2tlb.tid),
                                         .dout(ctx_reg), 
                                         .luterr(ctx_luterr));
                                         
        
endmodule


module immutlb_fast #(parameter bit LARGEPAGETLB=1'b1) (input iu_clk_type gclk, input rst, 
             input  mmu_iu_itlb_type      iu2tlb,
             input  mmu_mmumem_itlb_type  mem2tlb,
             output mmu_itlb_iu_type      tlb2iu,
//             output bit                   exception,
//             output bit [1:0]             fault_type,
//             output mmu_itlb_mmumem_type  tlb2mem,            
             output bit                   tlbmiss,             //need a tlb lookup
             output mmu_control_register_ram_type immu_ctrl_reg,
             output mmu_context_register_ram_type immu_ctx_reg,
            //soft error protection 
             output bit                   sberr,
             output bit                   dberr,
             output bit                   luterr           
            );

        
        mmu_iu_itlb_type  delr1_iu2tlb, delr2_iu2tlb, iu2tlbram;       //internal pipeline registers        

        mmu_itlb_iu_type  tlbram2iu, /*r_tlbram2iu,*/ v_tlb2iu;
        bit               tlbram_luterr;    
        
                
        //mmu register control
        mmu_control_register_ram_type ctrl_reg, r_ctrl_reg, new_ctrl_reg;
        mmu_context_register_ram_type ctx_reg, r_ctx_reg, new_ctx_reg;
        bit               ctrl_reg_we, ctx_reg_we;
        bit               ctrl_luterr, ctx_luterr;
    
        //flush state
        typedef struct packed{
          bit [ITLBINDEXMSB:ITLBINDEXLSB]   index;          //working index
          tlb_flush_probe_op_type           op;
          bit                               parity;
        }itlb_flush_state_type;
        
        //flush data
        typedef struct packed {
          bit [MMUCTXMSB:0]	  ctx;
          bit [31:12]         va;
          bit                 parity;
        }itlb_flush_data_type;
        
        
        (* syn_ramstyle = "select_ram" *) itlb_flush_state_type    flush_state[0:NTHREAD-1];  //one read port two write ports
        (* syn_ramstyle = "select_ram" *) itlb_flush_data_type       flush_data[0:NTHREAD-1];   //one read port one write port
        (* syn_maxfan = 16 *) bit [NTHREADIDMSB:0]                 flush_data_addr, flush_state_raddr, flush_state_waddr;           //TDM addr                
        itlb_flush_data_type       flush_wdata, flush_rdata;
        itlb_flush_state_type    flush_wstate, flush_rstate;                                  
        bit                      flush_state_we;
        bit                      flush_data_luterr, flush_state_luterr;
        
        mmu_tlb_flush_probe_type       flush2tlbram;
        
        tlb_flush_probe_op_type        r_flush_op;

        bit                      tlbstat;
        bit                      mmumem_en;
        
        always_comb begin                                                        
                                      
              //tlb->iu
              //v_tlb2iu = r_tlbram2iu;
              v_tlb2iu = tlbram2iu;
              if (!r_ctrl_reg.e) v_tlb2iu.pte.ppn = unsigned'({delr2_iu2tlb.vpn_tag, delr2_iu2tlb.index});     //no translation   
              if (r_flush_op != flush_probe_none) v_tlb2iu.valid = '0;  //mmu is busy with flush
              
              tlb2iu         = v_tlb2iu;
              immu_ctrl_reg  = r_ctrl_reg;
              immu_ctx_reg   = r_ctx_reg;
                                               
              //mmu register interface        
              ctrl_reg_we = (rst == 1'b1 || mem2tlb.op == update_ctrl_reg)? '1 :'0;
              ctx_reg_we  = (mem2tlb.op == update_ctx_reg)? '1 :'0;
              
              new_ctrl_reg = (LUTRAMPROT) ? {^mem2tlb.mmureg[1:0],mem2tlb.mmureg[1:0]} : {1'b0, mem2tlb.mmureg[1:0]};                            
              new_ctx_reg  = (LUTRAMPROT) ? {^mem2tlb.mmureg[MMUCTXMSB:0],mem2tlb.mmureg[MMUCTXMSB:0]} : {1'b0, mem2tlb.mmureg[MMUCTXMSB:0]};

              //flush control logic
              flush_data_addr = (gclk.ce) ? iu2tlb.tid : mem2tlb.tid; 
              flush_wdata.va  = mem2tlb.mmureg[31:12];
              flush_wdata.ctx = mem2tlb.mmureg[MMUCTXMSB:0];
              
              
              flush_wdata.parity = (LUTRAMPROT)? ^{flush_wdata.ctx, flush_wdata.va} : '0;              
              flush_data_luterr = (LUTRAMPROT) ? ^flush_rdata : '0;
              
              //flush fsm
              flush_state_raddr = iu2tlb.tid;
              flush_rstate = flush_state[flush_state_raddr];
              if (gclk.ce) begin      
                flush_state_we  = (flush_rstate.op != flush_probe_none || rst) ? '1 : '0;                
                flush_wstate.op = (flush_rstate.op == flush_probe_l3 || flush_rstate.index == LASTITLBINDEX || rst) ? flush_probe_none : flush_rstate.op;
                flush_wstate.index = flush_rstate.index + 1;  //inc the flush index 
                flush_state_waddr = delr1_iu2tlb.tid;
              end
              else begin                
                flush_wstate.index =  '0;
                flush_state_we = '1;
                unique case(mem2tlb.op)     //assume we have <64 tlbs per-thread
                tlb_flush_l3: flush_wstate.op = flush_probe_l3;
                tlb_flush_l2: flush_wstate.op = flush_probe_l2;
                tlb_flush_l1: flush_wstate.op = flush_probe_l1;
                tlb_flush_l0: begin flush_wstate.op = flush_probe_l0; flush_wstate.index = mem2tlb.mmureg[ITLBINDEXMSB:ITLBINDEXLSB]; end
                tlb_flush_all: flush_wstate.op = flush_probe_all;
                default: begin flush_wstate.op = flush_probe_none; flush_state_we = '0; end
                endcase
                flush_state_waddr = mem2tlb.tid;                              
              end
              
              flush_wstate.parity = (LUTRAMPROT) ? ^{flush_wstate.index , flush_wstate.op} : '0;
              flush_state_luterr = (LUTRAMPROT) ? ^flush_rstate : '0;
              
              //iu->tlbram
              flush2tlbram = {r_flush_op, flush_rdata.ctx, flush_rdata.va};
              iu2tlbram    = iu2tlb;
              if (flush_rstate.op != flush_probe_none)
                iu2tlbram.index = flush_rstate.index;
                    
              //error detection interface
              luterr = ctrl_luterr | ctx_luterr | tlbram_luterr | flush_data_luterr | flush_state_luterr;
        end
        
   
        //pipeline registers   
        always_ff @(posedge gclk.clk) begin
          delr1_iu2tlb <= iu2tlb;
          delr2_iu2tlb <= delr1_iu2tlb;
          
          r_ctrl_reg <= ctrl_reg;
          r_ctx_reg  <= ctx_reg;
          
//          r_tlbram2iu <= tlbram2iu;
          mmumem_en <= (r_flush_op == flush_probe_none) ? '1 : '0;
        end   
        
        /*
         //tlb->mem output register
        always_ff @(posedge gclk.clk) begin
          tlb2mem.tid <= delr2_iu2tlb.tid;
          tlb2mem.vpn <= {delr2_iu2tlb.vpn_tag, delr2_iu2tlb.index};
          tlb2mem.ctx <= r_ctx_reg;
          tlb2mem.op  <= (delr2_iu2tlb.valid & mmumem_en & ~r_tlbram2iu.valid & ~tlbstat) ? tlbmem_read_miss : tlbmem_none; 
        end
        */
        
        //we need a tlb lookup
        //assign tlbmiss = delr2_iu2tlb.valid & mmumem_en & ~r_tlbram2iu.valid & ~tlbstat; 
        
        //flush data ram
        always_ff @(negedge gclk.clk) begin
          if (mem2tlb.op == tlb_flush_all || mem2tlb.op == tlb_flush_l0 || mem2tlb.op == tlb_flush_l1 || mem2tlb.op == tlb_flush_l2 || mem2tlb.op == tlb_flush_l3)
            flush_data[flush_data_addr] <= flush_wdata;
        end
        always_ff @(posedge gclk.clk) flush_rdata <= flush_data[flush_data_addr];
        
        //flush state ram
        always_ff @(posedge gclk.clk2x) if (flush_state_we) flush_state[flush_state_waddr] <= flush_wstate;
        always_ff @(posedge gclk.clk2x) if (gclk.ce) r_flush_op <= flush_rstate.op;
          
        generate 
          if (LARGEPAGETLB) begin
            itlbram_2way_split_fast itlbram_split(.gclk,.rst, 
                                             .iu2tlb(iu2tlbram),
                                             .ctx(ctx_reg.ctx),		        //ctx ID
                                             .tlbflush(flush2tlbram),
                                             .mem2tlb,
                                             .tlbram2iu,
                                             .tlbstat,
                                             .sberr,
                                             .dberr,
                                             .luterr(tlbram_luterr));
          end
          else begin    //Todo: implement 4-way set assoc unified TLB

          end
        endgenerate
        
        //instantiate control and context register
        mmu_control_register   #(.DOREG(0)) gen_ctrl_reg(.gclk, 
                                         .din(new_ctrl_reg),
                                         .we(ctrl_reg_we),
                                         .wtid(mem2tlb.tid),
                                         .rtid(delr1_iu2tlb.tid),
                                         .dout(ctrl_reg), 
                                         .luterr(ctrl_luterr));

        mmu_context_register   #(.DOREG(0)) gen_ctx_reg(.gclk, 
                                         .din(new_ctx_reg),
                                         .we(ctx_reg_we),
                                         .wtid(mem2tlb.tid),
                                         .rtid(delr1_iu2tlb.tid),
                                         .dout(ctx_reg), 
                                         .luterr(ctx_luterr));
                                         
        
endmodule
  

module immu_if 
     (input iu_clk_type gclk, input rst, 
 	    //mmu ctrl<-> iu interface 
	    input  immu_iu_in_type	  immu_if_in,	
    	 output immu_iu_out_type 	immu_de_out,		//DE stage output	
     	//--------------------TLB interface------------------
	    //itlb <-> mem interface
	    input  mmu_mmumem_itlb_type  mem2tlb,
//	    output mmu_itlb_mmumem_type  tlb2mem,
	    //----------------------------------------------------
	    //mmu ctrl-> icache interface
	    output icache_de_in_type 	icache_de_in, 		//icache input at DE stage
      //soft error protection 
      output bit                   sberr,
      output bit                   dberr,
      output bit                   luterr           	 
	);		
	
	//--------------pipeline registers--------------		
	typedef struct {
    bit [NTHREADIDMSB:0]    tid;
		bit		      valid;		    //lookup is valid
		bit [31:2]	vpc;		      //virtual pc	
		bit        su;         //supervisor mode
	}delr_if_type; 		//if register type

	typedef struct {		
		bit				              valid;		      //lookup is valid
		bit [31:ITLBINDEXLSB] paddr;		      //physical address				
		bit                   su;
    bit                   exception;
		//decode stage input 
    bit                   iflush;      //flush i$?
    bit [FLUSHIDXMSB:0]   flushidx;    //flush index  
	}delr_de_type;		//de register type
	
	delr_if_type		delr_if;	//pipeline registers
	delr_de_type		delr_de;	
	

	bit [31:0]		         paddr;		     //physical address				


  mmu_iu_itlb_type		            iu2tlb;		
	mmu_itlb_iu_type 	            tlb2iu; 
	mmu_control_register_ram_type immu_ctrl_reg;
	mmu_context_register_ram_type immu_ctx_reg;
	bit                           tlbmiss;
	bit                           itlb_replay;       //replay caused by flush tlb
  
  //mmu exception signals
  bit [2:0]         mmuat;
  bit [2:0]         mmuft;        
  bit               exception;   //exception


  //unrecoverable errors
  bit                 mmu_dberr, mmu_luterr;
  
  always_comb begin        
	  icache_de_in.iflush   = delr_de.iflush;
	  icache_de_in.flushidx = delr_de.flushidx;     
	  
	  //iu -> itlb interface	  
	  iu2tlb.tid     = immu_if_in.tid;
    iu2tlb.vpn_tag = immu_if_in.vpc[31:ITLBTAGLSB];
	  iu2tlb.index   = immu_if_in.vpc[ITLBINDEXMSB:ITLBINDEXLSB];
	  iu2tlb.index1  = immu_if_in.vpc[18 +: log2x(NITLBENTRY)];
//	  iu2tlb.replay  = immu_if_in.replay;
//	  iu2tlb.valid   = immu_if_in.valid & ~immu_if_in.iflush;
    iu2tlb.valid   = immu_if_in.valid;
	  
	  //exception detection
    mmuat = (delr_de.su) ? MMU_AT_LOADEXE_FROM_KERNEL_INST : MMU_AT_LOADEXE_FROM_USER_INST;
    mmuft = detect_mmu_fault(mmuat, tlb2iu.pte);

    exception = (tlb2iu.valid & immu_ctrl_reg.e & (~immu_ctrl_reg.nf | delr_de.su) & (mmuft != MMU_FT_NONE)) ? '1 : '0;

    immu_de_out.data.l       = tlb2iu.lvl;
    immu_de_out.data.at      = mmuat;
    immu_de_out.data.ft      = mmuft;
    immu_de_out.data.tlbmiss = tlbmiss & ~itlb_replay;    //no mmu walk if busy with flush

    immu_de_out.data.ctrl_reg.nf = immu_ctrl_reg.nf;
    immu_de_out.data.ctrl_reg.e  = immu_ctrl_reg.e;
    immu_de_out.data.ctx_reg     = immu_ctx_reg.ctx;
  
//		parity_error.tag_parity = '0;
//		parity_error.data_parity = '0;			

		if (MMUEN==0) begin	//mmu is disabled
      icache_de_in.paddr    = delr_de.paddr;
			icache_de_in.tlb_hit = '1;		//run & !annul & !ucmode			
//			icache_de_in.rtype = ICACHE_LD;			//don't care
			icache_de_in.exception = '0;	
			icache_de_in.valid = delr_de.valid;	
			immu_de_out.data.exception = '0;
			immu_de_out.parity_error = '0;				
		end	
		else begin    //MMU support      
		   icache_de_in.tlb_hit = delr_de.valid & ~tlbmiss & ~itlb_replay;		//make sure we get a hit if mmu bypass, b/c the icache logic needs that
//		   icache_de_in.rtype   = ICACHE_LD;			//don't care
       icache_de_in.valid   = delr_de.valid;	
       icache_de_in.paddr   = get_new_ppn(tlb2iu.pte, tlb2iu.lvl, delr_de.paddr);
       icache_de_in.exception = exception;
       immu_de_out.data.exception  = exception;
       immu_de_out.parity_error = mmu_dberr | mmu_luterr;                     
    end
  end
  
  
  generate 
      if (MMUEN) begin
        immutlb #(.LARGEPAGETLB(1'b1)) gen_immutlb(.*, .dberr(mmu_dberr), .replay(itlb_replay), .luterr(mmu_luterr));		
        
        assign dberr  = mmu_dberr;
        assign luterr = mmu_luterr;
      end
      else begin
        assign sberr  = '0;
      		assign dberr  = '0;
  	 	 	 assign luterr = '0;
      end
	endgenerate	
	

	always_ff @(posedge gclk.clk) begin
    delr_if.tid   <= immu_if_in.tid;              //optimized by shared register if necessary
		delr_if.valid <= immu_if_in.valid;
		delr_if.vpc   <= immu_if_in.vpc;
		delr_if.su    <= immu_if_in.su;
		
		delr_de.valid  <= delr_if.valid; 
    delr_de.su     <= delr_if.su;
		delr_de.iflush   <= immu_if_in.iflush;
		delr_de.flushidx <= immu_if_in.flushidx;

		delr_de.paddr     <= delr_if.vpc[31:ITLBINDEXLSB];		
		
		if (MMUEN == 0)		begin		
			delr_de.exception <= '0;
		end
		else begin   //replace with real mmu implementation
			delr_de.exception <= '0;
    end
	end		
endmodule
  
//------------------------old i-mmu------------------------------------------
module immu #(parameter DUMMYMMU = 0)
     (input iu_clk_type gclk, input rst, 
 	    //mmu ctrl<-> iu interface 
	    input  immu_iu_in_type	  immu_if_in,	
    	 output immu_iu_out_type 	immu_de_out,		//DE stage output	
     	//--------------------TLB interface------------------
	    //itlb <-> iu/mmu interface
	    output tlb_in_type		 iu2itlb,		
	    input  tlb_out_type 	itlb2iu, 
	    //memory <-> itlb interface 
	    input  tlb_in_type		 mem2itlb,		//mem interface (mmu walk)
	    output tlb_out_type 	itlb2mem,		//tlb mem interface to IU
	    //----------------------------------------------------
	    //mmu ctrl-> icache interface
	    output icache_de_in_type 	icache_de_in, 		//icache input at DE stage
	    output tlb_error_type	    parity_error		//to monitor circuit
	);		
	
	//--------------pipeline registers--------------		
	typedef struct {
		bit		      valid;		    //lookup is valid
		bit [31:2]	vpc;		      //virtual pc	
		bit        su;         //supervisor mode
	}delr_if_type; 		//if register type

	typedef struct {		
		bit				             valid;		      //lookup is valid
		bit [31:ITLBINDEXLSB]		paddr;		      //physical address				
    bit                  exception;
		//decode stage input 
    bit                   iflush;      //flush i$?
    bit [FLUSHIDXMSB:0]   flushidx;    //flush index  
	}delr_de_type;		//de register type
	
	delr_if_type		delr_if;	//pipeline registers
	(* syn_preserve=1 *)delr_de_type		delr_de;	
	
	assign icache_de_in.paddr    = delr_de.paddr;
	assign icache_de_in.iflush   = delr_de.iflush;
	assign icache_de_in.flushidx = delr_de.flushidx;
	
	bit [31:0]		         paddr;		     //physical address				

  bit [31:0]           compare_seg; //dummy compare segment
  bit                  exception;   //exception
  
	generate
		if (MMUEN==0) begin	//mmu is disabled
			assign icache_de_in.tlb_hit = '1;		//run & !annul & !ucmode			
		//	assign icache_de_in.rtype = ICACHE_LD;			//don't care
			assign icache_de_in.exception = '0;	
			assign icache_de_in.valid = delr_de.valid;	
			assign immu_de_out.data.exception = '0;
			assign immu_de_out.parity_error = '0;	
			assign parity_error.tag_parity = '0;
			assign parity_error.data_parity = '0;
		end	
		else if (DUMMYMMU) begin
		  assign icache_de_in.tlb_hit = '1;
	//	  assign icache_de_in.rtype = ICACHE_LD;			//don't care
      assign icache_de_in.valid = delr_de.valid;	
      assign icache_de_in.exception = delr_de.exception;
      assign immu_de_out.data.exception = delr_de.exception;
      assign immu_de_out.parity_error = '0;	
      assign parity_error.tag_parity  = '0;
      assign parity_error.data_parity = '0;
		end
	endgenerate	
	
	always_comb begin
		//first cycle read, second cycle write
		iu2itlb.read.index.I <= immu_if_in.vpc[ITLBINDEXMSB:ITLBINDEXLSB];
		iu2itlb.read.tid <= immu_if_in.tid;

    //dummy MMU translation
    if (DUMMYMMU) begin
      exception = '0;
      compare_seg = MMU_COMPARE_MASK & {delr_if.vpc,2'd0};

      if (compare_seg >= USER_STACK_VIRTUAL_START && compare_seg < KERNEL_VIRTUAL_START)   //user stack
         paddr =  {delr_if.vpc,2'd0} & USER_OFFSET_MASK | USER_STACK_PHYSICAL_START; 
      else if (compare_seg >= KERNEL_VIRTUAL_START)  begin                                 //kernel 
         paddr =  {delr_if.vpc,2'd0} & KERNEL_OFFSET_MASK | KERNEL_PHYSICAL_START; 
         exception =~delr_if.su;        
      end
      else begin
         paddr = {delr_if.vpc,2'd0};
      end
    end  
	end
	

	always_ff @(posedge gclk.clk) begin
		delr_if.valid <= immu_if_in.valid;
		delr_if.vpc   <= immu_if_in.vpc;
		delr_if.su    <= immu_if_in.su;
		
		delr_de.valid  <= delr_if.valid; 

		delr_de.iflush   <= immu_if_in.iflush;
		delr_de.flushidx <= immu_if_in.flushidx;
		
		if (MMUEN == 0)		begin
			delr_de.paddr     <= delr_if.vpc[31:ITLBINDEXLSB];
			delr_de.exception <= '0;
		end
		else	if (DUMMYMMU) begin
			delr_de.paddr     <= paddr[31:ITLBINDEXLSB];	
			delr_de.exception <= exception;
		end
		else begin   //Todo: replace with real mmu implementation
			delr_de.paddr     <= delr_if.vpc[31:ITLBINDEXLSB];
			delr_de.exception <= '0;
    end
	end		
endmodule
