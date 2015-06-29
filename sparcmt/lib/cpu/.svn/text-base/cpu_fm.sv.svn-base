//-------------------------------------------------------------------------------------------------  
// File:        cpu_fm.sv
// Author:      Zhangxi Tan 
// Description: Composable cpu function model with MMU enabled
//-------------------------------------------------------------------------------------------------

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libopcodes::*;
import libiu::*;
import libxalu::*;
import libmmu::*;
import libcache::*;
import libmemif::*;
import libio::*;
import libdebug::*;
import libtm::*;
import libtech::*;
import libeth::*;
import libperfctr::*;
`else
`include "../../lib/cpu/libiu.sv"
`include "../../lib/cpu/libmmu.sv"
`include "../../lib/cpu/libcache.sv"
`include "../../lib/cpu/libxalu.sv"
`include "../../lib/mem/libmemif.sv"
`include "../../lib/io/libio.sv"
`include "../../lib/tm/libtm.sv"
`include "../../lib/eth/libeth.sv"
`include "../../lib/tm/perfctr/libperfctr.sv"
`endif


module cpu_fm #(parameter NONECCDRAM = "FALSE", parameter int PID= 0) (input iu_clk_type gclk, input bit rst,
    //IO interface to timing model
    output io_bus_in_type      tm_io_in,                     
    input  io_bus_out_type     tm_io_out,
   
    //dma buffer interface
    output debug_dma_read_buffer_in_type   dma_rb_in,
    input  debug_dma_read_buffer_out_type  dma_rb_out,
    output debug_dma_write_buffer_in_type  dma_wb_in,

    //dma command interface 
    input  debug_dma_cmdif_in_type         dma_cmd_in,     //cmd input 
//    output bit                             dma_cmd_ack,    //cmd has been accepted (no lo
    //dma status
    output bit                             dma_done,
    
    //memory network interface
    output mem_ctrl_in_type                imem_in,
    output mem_ctrl_in_type                dmem_in,
    input  mem_ctrl_out_type               imem_out,
    input  mem_ctrl_out_type               dmem_out,
  
    
    //timing model interface
    output tm_cpu_ctrl_token_type          cpu2tm,
    input  tm2cpu_token_type               tm2cpu,
    input  bit                             tick,        //for timer
    input  bit                             running,

    
    //host performance counter interface
    output bit [11:0]                     host_global_perf_counter ,    //you might want to put more counters here

    //error output
    output bit                             error_mode,   //error mode 
    output bit                             ram_error    //any ram error
    
    );

  bit       xc_error_mode, xc_error_r, xc_error_out;
  

  
  //----------wires----------
  //pipeline registers
  commit_reg_type   comr;   //WB -> IF, WB -> REG
  decode_reg_type   der;    //IF -> DE
  reg_reg_type      regr;   //DE -> REG
  ex_reg_type       exr;    //REG -> EX
  mem_reg_type      memr;   //EX -> MEM
  xc_reg_type       xcr;    //MEM -> XC

  //immu
  immu_iu_in_type   immu_if_in;    //IF -> IMMU
  immu_iu_out_type  immu_de_out;   //IMMU -> DE
  
  //dmmu
  mmu_iu_dtlb_type       ex2mem_dmmu;    //input from ex1 stage to mmu, EX->MEM
  mmu_host_cache_in_type mmu2hc;         //output from dmmu @EX2/MEM1, DMMU->MEM
  bit			                 mmu2hc_invalid;

  dmmu_if_iu_in_type    iu2dmmu;    //IU -> DMMU
  dmmu_iu_out_type  dmmu2iu;    //DMMU -> IU
  

  mmu_mmumem_itlb_type dmmu2immu; //DMMU->IMMU
        
  bit                  itlb_miss, dtlb_miss;

  //I$
  icache_if_in_type     icache_if_in;          //IF -> I$
  icache_data_out_type  icache_if_out;         //I$ -> IF
  cache2iu_ctrl_type    icache_de_out;         //I$ -> DE
  icache_de_in_type     icache_de_in;          //IMMU->I$

  mem_stat_out_type     icache_mem2iu_stat;  //memory status -> I$
  bit [NTHREADIDMSB:0]  icache_iu2mem_tid;    //I$ -> memory ctrl
  mem_cmd_in_type       icache_iu2mem_cmd;    //I$ -> memory ctrl 
  
  cache_ram_in_type     icache_mem2cacheram; //mem -> I$ ram
  cache_ram_out_type    icache_cacheram2mem;  //I$ ram -> mem
  
  //D$
  dcache_data_out_type  dcache_data;          //D$ -> IU
  dcache_iu_in_type     iu2dcache;            //IU -> D$ 
//  dcache_mmu_in_type    dmmu2cache;           //DMMU->D$
  mmu_host_cache_out_type dcache2mmu;          // D$ -> DMMu
  cache2iu_ctrl_type    dcache2iu;             //D$ -> IU control

  mem_stat_out_type     dcache_mem2iu_stat;   //memory status -> D$
  bit [NTHREADIDMSB:0]  dcache_iu2mem_tid;    //D$ -> memory ctrl
  mem_cmd_in_type       dcache_iu2mem_cmd;    //D$ -> memory ctrl

  cache_ram_in_type     dcache_mem2cacheram; //mem -> D$ ram
  cache_ram_out_type    dcache_cacheram2mem;  //D$ ram -> mem


  //dma_interface
  debug_dma_in_type     iu2dma;
  debug_dma_out_type    dma2iu;
  bit [NTHREADIDMSB:0]  dma_rtid;   //(IU) read DMA register
  
  //timing model interface
  tm_dbg_ctrl_type       dma2cpu;     //start and stop everything right now
  
  //io bus signals to CPU
  io_bus_out_type      io_in;
  io_bus_in_type       io_out;
  
  io_bus_out_type      irq_io_out;
  
  bit                  irqack;
  bit                  irq_timer;
  
  //-------------------------SEU errors---------------------------
  //lutram errors
  bit [8:0] luterr_r;
  bit   if_lutram_err;          //IF lutram error
  bit   de_lutram_err;          //DE lutram error
  bit   ex_lutram_err;          //EX lutram error
  bit   xc_lutram_err;          //XC lutram error
  bit   imem_if_lutram_err;   //imem if lutram error
  bit   dmem_if_lutram_err;   //imem if lutram error
  bit   dma_luterr;            //DMA register lutram error
  bit   dmmu_lutram_err;      //DMMU lutram error
  bit   immu_lutram_err;      //IMMU lutram error

  //bram errors
  bit [4:0] bramerr_r;
  bit        de_bram_err;     //DE bram error
  bit        ex_bram_err;     //EX bram error
  bit        xc_bram_err;     //XC bram error
  bit        dmmu_dberr, immu_dberr;
  (* syn_srlstyle="registers" *) bit [1:0] r_dmmu_dberr, r_immu_dberr;

//  tlb_error_type  itlb_error, dtlb_error;   //TLB bram parity errors

  //single bit errors corrected by ECC
  bit [3:0] sb_ecc_r;
  bit        de_sb_ecc;       //DE sb error
  bit        xc_sb_ecc;       //XC sb error
  bit 		 dmmu_sberr, immu_sberr;
  (* syn_srlstyle="registers" *) bit [1:0]        r_dmmu_sberr, r_immu_sberr;

  //output registers
  bit        luterr_out;
  bit        bramerr_out;
  bit        sb_ecc_out;
  
  //wire of performance counter
  bit   dcacheblkcnt, dcacherawcnt;
  //performance counter registers
  (* syn_srlstyle="registers" *) bit [1:0]  hostcycle_en;
  (* syn_srlstyle="registers" *) bit [1:0]  icmiss_en;
  (* syn_srlstyle="registers" *) bit [1:0]  ldmiss_en;
  (* syn_srlstyle="registers" *) bit [1:0]  itlbmiss_en;
  (* syn_srlstyle="registers" *) bit [1:0]  dtlbmiss_en;
  (* syn_srlstyle="registers" *) bit [1:0]  stmiss_en;
  (* syn_srlstyle="registers" *) bit [1:0]  nretired_en;
  (* syn_srlstyle="registers" *) bit [1:0]  ldst_en;
  (* syn_srlstyle="registers" *) bit [1:0]  blkcnt_en, rawcnt_en;
  (* syn_srlstyle="registers" *) bit [1:0]  replay_en, idlecnt_en, microcode_en, replaymul_en, replayfpu_en;
  bit   comr_r_run, comr_run, comr_r_dma, comr_dma; 
  
  //flight recorder signals
  /*
  typedef struct packed {
    bit [31:0] inst;
    bit [29:0] pc;
    bit [5:0]  tid;
    bit      ucmode;
    bit      replay;
    bit      run;
    bit      dma_mode;
    bit      error_mode;
    bit      icmiss;
    bit 	    irq;
    bit      mmu_replay;
    bit      dcache_replay;
    bit		    itlbmiss;
    bit      itlbexception;
    bit	     dtlbexception;
    bit		    immu_refill;
  }flight_recorder_data_type;
  bit [127:0]   ic_wdata;
  bit [127:0]   icacheram_dbg_out;
  bit [8:0]   icacheram_read_addr;
  
  immu_data_type	m2_immu_data, xc_immu_data;
      
  localparam FDRWIDTH = $bits(flight_recorder_data_type);
    
  (* syn_preserve=1 *) flight_recorder_data_type fr_din;
  flight_recorder_data_type fr_dout;
  (* syn_noprune=1 *) flight_recorder_data_type  fr_dout_r;
  (* syn_noprune=1 *) bit fdr_trigger;
  (* syn_noprune=1 *) bit[4:0] fdr_trigger_cnt;
*/
  //------------------generate IO bus to CPU------------------------
  always_comb begin
    io_in = tm_io_out;                
    io_in.irl = irq_io_out.irl;
    tm_io_in  = io_out;
  end

  //------------------generate integer pipeline---------------------
  
  //fetch
  fetch_stage_dma   #(.newsch(1'b1)) gen_if(.*, .luterr(if_lutram_err));
  //decode stage
  decode_stage    gen_de(.*, .immu2iu(immu_de_out), .luterr(de_lutram_err), .bramerr(de_bram_err), .sb_ecc(de_sb_ecc));
  //regacc stage
  regacc_stage_dma  gen_regacc(.*);
  //execuation stage
  execution_stage   #(.DOREG(1'b1)) gen_ex(.*, .luterr(ex_lutram_err), .bramerr(ex_bram_err), .iu2dtlb(ex2mem_dmmu));
  //memory stage
  memory_stage    #(.INREG(1)) gen_mem(.*, .iu2dtlb(ex2mem_dmmu), .mmu2hc);
  //exception stage
  exception_stage_dma gen_xc(.*, .luterr(xc_lutram_err), .bramerr(xc_bram_err), .sb_ecc(xc_sb_ecc), .errmode(xc_error_mode), .irqack(irqack));
    
  //------------------generate mmu---------------------
  immu_if  gen_immu(.*, .mem2tlb(dmmu2immu), .sberr(immu_sberr), .dberr(immu_dberr), .luterr(immu_lutram_err));
  dmmu_if  gen_dmmu(.*, .toitlb(dmmu2immu), .mmu2hc,	.hc2mmu(dcache2mmu), .mmu2hc_invalid,	/*.mmu2hcfsm(dmmu2cache),*/ .sberr(dmmu_sberr), .dberr(dmmu_dberr), .luterr(dmmu_lutram_err));

  //------------------generate cache---------------------
  icache    #(.read2x(1), .write2x(1), .NONECCDRAM(NONECCDRAM))  gen_icache(.gclk, .rst, 
          .mem2iu_stat(icache_mem2iu_stat), 
          .iu2mem_tid(icache_iu2mem_tid),
          .iu2mem_cmd(icache_iu2mem_cmd),
          .mem2cacheram(icache_mem2cacheram), 
          .cacheram2mem(icache_cacheram2mem),
          .iu2cache(icache_if_in),
          .immu2cache(icache_de_in),
          .if_out(icache_if_out),
          .de_out(icache_de_out));

  //dcache    #(.read2x(1), .write2x(1))  gen_dcache(.gclk, .rst, 
  dcache_udc    #(.read2x(1), .write2x(1), .NONECCDRAM("FALSE"))  gen_dcache(.gclk, .rst, 
          .mem2iu_stat(dcache_mem2iu_stat), 
          .iu2mem_tid(dcache_iu2mem_tid),
          .iu2mem_cmd(dcache_iu2mem_cmd),
          .mem2cacheram(dcache_mem2cacheram), 
          .cacheram2mem(dcache_cacheram2mem),
          .iu2cache(iu2dcache),
          .data_out(dcache_data),
          .dcache2iu,
          .dmmu_invalid(mmu2hc_invalid),
          .*);

  //------------------generate memory IF-------------------
  imem_if   #(.read2x(1), .write2x(1))  gen_imem_if(.gclk, .rst,
          .iu2mem_tid(icache_iu2mem_tid),
          .iu2mem_cmd(icache_iu2mem_cmd),
          .mem2iu_stat(icache_mem2iu_stat),
          .cacheram2mem(icache_cacheram2mem),
          .mem2cacheram(icache_mem2cacheram),
          .from_mem(imem_out),
          .to_mem(imem_in),
          .luterr(imem_if_lutram_err));

  dmem_if   #(.read2x(1), .write2x(1), .nonblocking(1)) gen_dmem_if(.gclk, .rst,
          .iu2mem_tid(dcache_iu2mem_tid),
          .iu2mem_cmd(dcache_iu2mem_cmd),
          .mem2iu_stat(dcache_mem2iu_stat),
          .cacheram2mem(dcache_cacheram2mem),
          .mem2cacheram(dcache_mem2cacheram),
          .from_mem(dmem_out),
          .to_mem(dmem_in),
          .luterr(dmem_if_lutram_err));

  
  //------------------generate DMA controller----------------
  debug_dma   gen_iu_dma(.*, .dma_cmd_ack(), .luterr(dma_luterr));

  //----------generate IRQ & timer-------------
  timer #(.addrmask(1)) gen_timer (.*, 
             // CPU interface
             .bus_in(io_out),
             .tick,
             .irq(irq_timer)                  //@M2
            );

   irqmp #(.NIRQ(1), .addrmask(2)) gen_irqmp(.*,
             // CPU interface
             .bus_in(io_out),
             .irqack,              //@xc
             .bus_out(irq_io_out),
             .irq(irq_timer)       //@M2
            );
    

  //----------host performance counters-------------
  
  always_ff @(posedge gclk.clk) begin
    hostcycle_en[0] <= running;
      
    icmiss_en[0]   <= icache_iu2mem_cmd.valid;
    ldmiss_en[0]   <= (running & (dcache_iu2mem_cmd.cmd.D == DCACHE_LD)) ? dcache_iu2mem_cmd.valid : '0;
    stmiss_en[0]   <= (running & (dcache_iu2mem_cmd.cmd.D == DCACHE_WB)) ? dcache_iu2mem_cmd.valid : '0;
    nretired_en[0] <= comr.spr.pc_we;
    ldst_en[0]     <= ~memr.ts.dma_mode & memr.ts.run & (memr.ts.inst[31:30] == LDST) & ~memr.ts.replay & ~memr.ts.ucmode;    //count a LDST even if it traps
    blkcnt_en[0]   <= xcr.ts.run & dcacheblkcnt;
    rawcnt_en[0]   <= xcr.ts.run & dcacherawcnt;
    
    itlbmiss_en[0] <= xcr.ts.run & itlb_miss;
    dtlbmiss_en[0] <= xcr.ts.run & dtlb_miss;
    
    comr_r_dma  <= xcr.ts.dma_mode;
    comr_dma    <= comr_r_dma;
    comr_r_run  <= xcr.ts.run;
    comr_run    <= comr_r_run;
    
    replay_en[0]    <= comr.spr.replay & ~comr_dma & comr_run;
    microcode_en[0] <= comr.spr.ucmode & comr_run & ~comr_dma & ~comr.spr.replay;
    idlecnt_en[0]   <= running & ~xcr.ts.run;
    
    if (xcr.ts.inst[31:30]==FMT3 && xcr.ts.replay & xcr.ts.run) begin
      unique case(xcr.ts.inst[24:19])
    UMUL, SMUL, UMULCC, SMULCC, ISLL, ISRL, ISRA : replaymul_en[0] <= '1;
    default: replaymul_en[0] <= '0;
    endcase
    end
    else
      replaymul_en[0] <= '0;

    if (xcr.ts.inst[31:30]==FMT3 && xcr.ts.replay & xcr.ts.run) begin
      unique case(xcr.ts.inst[24:19])
        FPOP1: unique case(xcr.ts.inst[13:5])
            FADDD, FSUBD, FMULD,FADDS, FSUBS, FMULS, FSMULD, FITOS,FITOD,FSTOI,FDTOI : replayfpu_en[0] <= '1;
            default: replayfpu_en[0] <= '0;
            endcase
        FPOP2: unique case(xcr.ts.inst[13:5])
          FCMPD, FCMPED, FCMPS, FCMPES : replayfpu_en[0] <='1;
          default: replayfpu_en[0] <= '0;
          endcase
        default:replayfpu_en[0] <= '0;
      endcase
    end
    else 
      replayfpu_en[0] <= '0;
          
      hostcycle_en[1] <= hostcycle_en[0];      
      icmiss_en[1]    <= icmiss_en[0];
      ldmiss_en[1]    <= ldmiss_en[0];
      stmiss_en[1]    <= stmiss_en[0];
      nretired_en[1]  <= nretired_en[0];
      ldst_en[1]      <= ldst_en[0];    //count a LDST even if it traps      
      blkcnt_en[1]    <= blkcnt_en[0];
      rawcnt_en[1]    <= rawcnt_en[0];
      replay_en[1]    <= replay_en[0];
      replaymul_en[1] <= replaymul_en[0];
      replayfpu_en[1] <= replayfpu_en[0];
      microcode_en[1] <= microcode_en[0];
      idlecnt_en[1]   <= idlecnt_en[0];
      itlbmiss_en[1] <= itlbmiss_en[0];
      dtlbmiss_en[1] <= dtlbmiss_en[0];      
  end

  assign host_global_perf_counter = {idlecnt_en[1], microcode_en[1], replayfpu_en[1], replaymul_en[1], replay_en[1], rawcnt_en[1], blkcnt_en[1], dtlbmiss_en[1], itlbmiss_en[1], stmiss_en[1], ldmiss_en[1], icmiss_en[1]};


    //------------------generate a flight recorder---------------------
  /*
  always_ff @(posedge gclk.clk) begin
   fr_din.inst       <= xcr.ts.inst;
   fr_din.pc         <= xcr.ts.pc;
   fr_din.tid        <= xcr.ts.tid;
   fr_din.ucmode     <= xcr.ts.ucmode;
   fr_din.replay     <= xcr.ts.replay;
   fr_din.mmu_replay <= dmmu2iu.replay;
   fr_din.dcache_replay <= dcache2iu.replay;
   fr_din.run        <= xcr.ts.run;
   fr_din.dma_mode   <= xcr.ts.dma_mode;
   fr_din.icmiss     <= xcr.ts.icmiss;
   fr_din.dtlbexception <= dmmu2iu.exception;
   fr_din.irq		 <= xcr.trap_res.irq_trap;
   
   fr_din.itlbexception   <= xc_immu_data.exception;
   fr_din.itlbmiss		  <= xc_immu_data.tlbmiss;   
   fr_din.immu_refill	  <= (dmmu2immu.op == tlb_refill);
   fr_din.error_mode      <= xc_error_mode;
   
   fr_dout_r <= fr_dout;
   
   m2_immu_data <= memr.immu_data;
   xc_immu_data <= m2_immu_data;
   
        if (rst | (xcr.ts.run & ~xcr.ts.replay & ~xcr.ts.ucmode & ~xcr.ts.dma_mode)) fdr_trigger_cnt <= '0;
        else if (xcr.ts.run & xcr.ts.replay & ~xcr.ts.ucmode & ~xcr.ts.dma_mode) fdr_trigger_cnt <= fdr_trigger_cnt + 1;
        
        fdr_trigger <= (fdr_trigger_cnt > 16) ? '1 : '0;
   end  
*/
//   flight_recorder #(.DWIDTH(FDRWIDTH)) fdr( .clk(gclk.clk), .rst, .din(fr_din), .dout(fr_dout)) /* synthesis syn_noprune=1 */;
  
  //------------------SEU Error detection logic-----------------
  always_ff @(posedge gclk.clk) begin
          r_dmmu_dberr <= {dmmu_dberr, r_dmmu_dberr[$bits(r_dmmu_dberr)-1:1]};
          r_immu_dberr <= {immu_dberr, r_immu_dberr[$bits(r_immu_dberr)-1:1]};
          r_dmmu_sberr <= {dmmu_sberr, r_dmmu_sberr[$bits(r_dmmu_sberr)-1:1]};
          r_immu_sberr <= {immu_sberr, r_immu_sberr[$bits(r_immu_sberr)-1:1]};
  end
  
  always_ff @(posedge gclk.clk2x) begin
    if (rst) begin 
      luterr_r <= '0;
      bramerr_r <= '0;
      sb_ecc_r <= '0;

      luterr_out <= '0;
      bramerr_out <= '0;
      sb_ecc_out <= '0;
    end
    else begin
      luterr_r <= {if_lutram_err, de_lutram_err, ex_lutram_err, xc_lutram_err, imem_if_lutram_err, dmem_if_lutram_err, dma_luterr, immu_lutram_err, dmmu_lutram_err};
      bramerr_r <= {de_bram_err, ex_bram_err, xc_bram_err,  r_dmmu_dberr[0], r_immu_dberr[0]};
      sb_ecc_r <= {de_sb_ecc, xc_sb_ecc, r_immu_sberr[0], r_dmmu_sberr[0]};

      luterr_out <= (luterr_out == 1'b0) ? |luterr_r : 1'b1;
      bramerr_out <= (bramerr_out == 1'b0) ? |bramerr_r : 1'b1;
      sb_ecc_out <= (sb_ecc_out == 1'b0) ? | sb_ecc_r : 1'b1;
      
    end   
  end
  
  always_ff @(posedge gclk.clk) begin
    if (rst)
      xc_error_out <= '0;
    else begin
      xc_error_r <= xc_error_mode;
      xc_error_out <= (xc_error_out == 1'b0) ? xc_error_r : 1'b1;
    end
  end
      
  assign error_mode = xc_error_out;
  assign ram_error = luterr_out | bramerr_out | sb_ecc_out;
  
  
  //connect to disassembler
  
  //synthesis translate_off
  disassembler #(.PID(PID)) gen_disasm(.gclk, .rst, .xcr, .dcache_replay(dcache2iu.replay | dmmu2iu.replay));
  //synthesis translate_on  
  
endmodule