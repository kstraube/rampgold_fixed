//-------------------------------------------------------------------------------------------  
// File:        top_1P_bram_dma.sv
// Author:      Zhangxi Tan
// Description: Top level design for one pipeline and BRAM memory with debug DMA engine
//-------------------------------------------------------------------------------------------   

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libxalu::*;
import libmmu::*;
import libcache::*;
import libmemif::*;
import libio::*;
import libtm::*;
import libdebug::*;
`else
`include "../../lib/cpu/libiu.sv"
`include "../../lib/cpu/libmmu.sv"
`include "../../lib/cpu/libcache.sv"
`include "../../lib/cpu/libxalu.sv"
`include "../../lib/tm/libtm.sv"
`include "../../lib/mem/libmemif.sv"
`include "../../lib/io/libio.sv"
`endif

module fpga_top(input bit clkin_p, input bit clkin_n, input bit rstin, input bit cpurst, output bit done_led, output bit error_led);
	iu_clk_type	gclk;            //global clock and clock enable
	bit		       rst;             //reset
	
	io_bus_out_type	io_in;

  //dma buffer master interface
  debug_dma_read_buffer_in_type   eth_rb_in;
  debug_dma_write_buffer_in_type  eth_wb_in;		//no use currently
  debug_dma_write_buffer_out_type eth_wb_out;		//no use currently				

	//dma buffer slave interface
  debug_dma_read_buffer_in_type   dma_rb_in;
  debug_dma_read_buffer_out_type  dma_rb_out;
  debug_dma_write_buffer_in_type  dma_wb_in;

	//dma command interface 
  debug_dma_cmdif_in_type         dma_cmd_in;     //cmd input 
  bit                             dma_cmd_ack;    //cmd has been accepted
	//dma status from IU
  bit                             dma_done;
  
  //dma timing model interface
  tm_dbg_ctrl_type               dma2tm;

	//init rom interface
	bit [15:0]			init_rom_addr;
	bit [31:0]			init_rom_data;

	assign io_in = '{default:0};
	
	//------------------generate clock and reset---------------------- 
	clkrst_gen_2	#(.differential(0)) gen_gclk_rst(.*, .rstin(~rstin), .dramrst(1'b0), .ram_clk(), .clkin_b());


	//generate cpu 
	cpu_top_dma		gen_cpu(.gclk, .rst, 
				.io_in,
				.io_out(),
				.luterr(),
				.bramerr(),
				.sb_ecc(),
    				.dma_rb_in,
    				.dma_rb_out,
				.dma_wb_in,
  				.dma_cmd_in,     //cmd input 
				.dma_cmd_ack,    //cmd has been accepted
    				.dma_done,
      		.dma2tm,
      		.error_led,
      		.done_led
				);
	
	//generate simulated DMA master
	dma_master	gen_dma_master(.gclk, .rst,
				       .eth_rb_in,
				       .eth_wb_in,		  //no use currently
				       .eth_wb_out,			//no use currently				
				       .dma_cmd_in,     
               .dma_cmd_ack,  //cmd has been accepted                
               .dma_done,		   //dma status
               .dma2tm,
					     //Init ROM interface
    					     .init_rom_addr,
					     .init_rom_data
				);
				
	//generate init rom
	simdma_init_rom gen_init_rom(.gclk, .rst, .raddr(init_rom_addr), .dout(init_rom_data));

  //generate generate the dual-port DMA buffer
  debug_dma_buf   gen_dma_buf(.*, .eth_rx_clk(gclk.clk), .eth_tx_clk(gclk.clk), .dberr(), .sberr());  
endmodule

module cpu_top_dma(input iu_clk_type gclk, input bit rst,
    //IO interface
    input  io_bus_out_type      io_in,
    output io_bus_in_type       io_out,
   
    //dma buffer interface
    output debug_dma_read_buffer_in_type   dma_rb_in,
    input  debug_dma_read_buffer_out_type  dma_rb_out,
    output debug_dma_write_buffer_in_type  dma_wb_in,
    //dma command interface 
    input  debug_dma_cmdif_in_type         dma_cmd_in,     //cmd input 
    output bit                             dma_cmd_ack,    //cmd has been accepted
    //dma timing model interface
    input  tm_dbg_ctrl_type                dma2tm,
    //dma status
    output bit                             dma_done,
    output bit                             done_led,  
    output bit                             error_led,
		output	bit 			                         luterr, 
		output	bit 			                         bramerr, 
		output	bit			                          sb_ecc  //interface to xalu
    );

  bit [15:0]      pc_count;
  bit             count_state;          
  
  
  const bit [31:0]    stopct_pc = 32'h2734;
  const bit [31:0]    error_pc  = 32'h1220;

  
	//----------wires----------
	//pipeline registers
	commit_reg_type		comr;		//WB -> IF, WB -> REG
	decode_reg_type		der;			//IF -> DE
	reg_reg_type		   regr;		//DE -> REG
	ex_reg_type		    exr;			//REG -> EX
	mem_reg_type		   memr;		//EX -> MEM
	xc_reg_type 		   xcr;			//MEM -> XC

	//immu
	immu_iu_in_type		immu_if_in;		 //IF -> IMMU
	immu_iu_out_type	immu_de_out;		//IMMU -> DE
	
	//dmmu
	dmmu_iu_in_type		iu2dmmu;		//IU -> DMMU
	dmmu_iu_out_type	dmmu2iu;		//DMMU -> IU

	//I$
	icache_if_in_type	   icache_if_in;		      //IF -> I$
	icache_data_out_type	icache_if_out;		     //I$ -> IF
	cache2iu_ctrl_type	  icache_de_out;		     //I$ -> DE
	icache_de_in_type	   icache_de_in;		      //IMMU->I$

	mem_stat_out_type	   icache_mem2iu_stat;  //memory status -> I$
	bit [NTHREADIDMSB:0]	icache_iu2mem_tid;	  //I$ -> memory ctrl
	mem_cmd_in_type		    icache_iu2mem_cmd;	  //I$ -> memory ctrl 
	
	cache_ram_in_type	   icache_mem2cacheram;	//mem -> I$ ram
	cache_ram_out_type	  icache_cacheram2mem;	//I$ ram -> mem
	
	//D$
	dcache_data_out_type	dcache_data;	       	//D$ -> IU
	dcache_iu_in_type	   iu2dcache;		         //IU -> D$ 
	dcache_mmu_in_type	  dmmu2cache;		        //DMMU->D$
	cache2iu_ctrl_type  	dcache2iu;		         //D$ -> IU control

	mem_stat_out_type	   dcache_mem2iu_stat;	 //memory status -> D$
	bit [NTHREADIDMSB:0]	dcache_iu2mem_tid;  	//D$ -> memory ctrl
	mem_cmd_in_type		    dcache_iu2mem_cmd;	  //D$ -> memory ctrl

	cache_ram_in_type	   dcache_mem2cacheram;	//mem -> D$ ram
	cache_ram_out_type	  dcache_cacheram2mem;	//D$ ram -> mem

	//mem interface
	mem_ctrl_in_type	    imem_in[0:0];
	mem_ctrl_in_type	    dmem_in[0:0];
	mem_ctrl_out_type	   imem_out[0:0];
	mem_ctrl_out_type	   dmem_out[0:0];

	//dma_interface
	debug_dma_in_type     iu2dma;
  debug_dma_out_type    dma2iu;
	bit [NTHREADIDMSB:0]		dma_rtid;		//(IU) read DMA register
	
	//timing model interface
	tm_cpu_ctrl_token_type cpu2tm;
  tm_dbg_ctrl_type       dma2cpu;     //start and stop everything right now
  tm_cpu_ctrl_token_type tm2cpu;

	//-------------------------SEU errors---------------------------
	//lutram errors
	bit [5:0]	luterr_r;
	bit		if_lutram_err;			    //IF lutram error
	bit		de_lutram_err;			    //DE lutram error
	bit		ex_lutram_err;			    //EX lutram error
	bit		xc_lutram_err;			    //XC lutram error
	bit		imem_if_lutram_err;		//imem if lutram error
	bit		dmem_if_lutram_err;		//imem if lutram error
	bit		dma_luterr;			//DMA register lutram error

	//bram errors
	bit [6:0]	bramerr_r;
	bit		     de_bram_err;			//DE bram error
	bit		     ex_bram_err;			//EX bram error
	bit		     xc_bram_err;			//XC bram error

	tlb_error_type	itlb_error, dtlb_error;		//TLB bram parity errors

	//single bit errors corrected by ECC
	bit [1:0]	sb_ecc_r;
	bit		     de_sb_ecc;			  //DE sb error
	bit		     xc_sb_ecc;			  //XC sb error

	//output registers
	bit		     luterr_out;
	bit		     bramerr_out;
	bit		     sb_ecc_out;
	

	//------------------generate integer pipeline---------------------
	
	//fetch
	fetch_stage_dma		gen_if(.*, .luterr(if_lutram_err));
	//decode stage
	decode_stage		gen_de(.*, .immu2iu(immu_de_out), .luterr(de_lutram_err), .bramerr(de_bram_err), .sb_ecc(de_sb_ecc));
	//regacc stage
	regacc_stage_dma	gen_regacc(.*);
	//execuation stage
	execution_stage		gen_ex(.*, .luterr(ex_lutram_err), .bramerr(ex_bram_err));
	//memory stage
	memory_stage		gen_mem(.*);
	//exception stage
	exception_stage_dma	gen_xc(.*, .luterr(xc_lutram_err), .bramerr(xc_bram_err), .sb_ecc(xc_sb_ecc));
		
	//------------------generate dummy mmu---------------------
	immu		#(.DUMMYMMU(0))	gen_immu(.gclk, .rst, .immu_if_in, .immu_de_out, .icache_de_in, .parity_error(itlb_error), .iu2itlb(), .itlb2iu(), .mem2itlb(), .itlb2mem());		//TLB interface are not connected
	dmmu		#(.DUMMYMMU(0))	gen_dmmu(.gclk, .rst, .iu2dmmu, .dmmu2iu, .dmmu2cache, .parity_error(dtlb_error), .iu2dtlb(), .dtlb2iu(), .mem2dtlb(), .dtlb2mem());

	//------------------generate cache---------------------
	icache			gen_icache(.gclk, .rst, 
					.mem2iu_stat(icache_mem2iu_stat), 
					.iu2mem_tid(icache_iu2mem_tid),
					.iu2mem_cmd(icache_iu2mem_cmd),
					.mem2cacheram(icache_mem2cacheram), 
					.cacheram2mem(icache_cacheram2mem),
					.iu2cache(icache_if_in),
					.immu2cache(icache_de_in),
					.if_out(icache_if_out),
					.de_out(icache_de_out));

	dcache			gen_dcache(.gclk, .rst, 
					.mem2iu_stat(dcache_mem2iu_stat), 
					.iu2mem_tid(dcache_iu2mem_tid),
					.iu2mem_cmd(dcache_iu2mem_cmd),
					.mem2cacheram(dcache_mem2cacheram), 
					.cacheram2mem(dcache_cacheram2mem),
					.iu2cache(iu2dcache),
					.dmmu2cache(dmmu2cache),
					.data_out(dcache_data),
					.dcache2iu);

	//------------------generate memory IF-------------------
	imem_if			gen_imem_if(.gclk, .rst,
					.iu2mem_tid(icache_iu2mem_tid),
					.iu2mem_cmd(icache_iu2mem_cmd),
					.mem2iu_stat(icache_mem2iu_stat),
					.cacheram2mem(icache_cacheram2mem),
					.mem2cacheram(icache_mem2cacheram),
					.from_mem(imem_out[0]),
					.to_mem(imem_in[0]),
					.luterr(imem_if_lutram_err));

	dmem_if			gen_dmem_if(.gclk, .rst,
					.iu2mem_tid(dcache_iu2mem_tid),
					.iu2mem_cmd(dcache_iu2mem_cmd),
					.mem2iu_stat(dcache_mem2iu_stat),
					.cacheram2mem(dcache_cacheram2mem),
					.mem2cacheram(dcache_mem2cacheram),
					.from_mem(dmem_out[0]),
					.to_mem(dmem_in[0]),
					.luterr(dmem_if_lutram_err));

	//------------------generate memory controller----------------
	blkmemctrl		gen_memctrl(.*);

	//------------------generate memory controller----------------
	debug_dma		gen_iu_dma(.*, .luterr(dma_luterr));

  //------------------generate timing model---------------------
  tm_cpu_none gen_tm(.*);
  
	//------------------SEU Error detection logic-----------------
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
			luterr_r <= {if_lutram_err, de_lutram_err, ex_lutram_err, xc_lutram_err, imem_if_lutram_err, dmem_if_lutram_err, dma_luterr};
			bramerr_r <= {de_bram_err, ex_bram_err, xc_bram_err, itlb_error.tag_parity, itlb_error.data_parity,  dtlb_error.tag_parity, dtlb_error.data_parity};
			sb_ecc_r <= {de_sb_ecc, xc_sb_ecc};

			luterr_out <= (luterr_out == 1'b0) ? |luterr_r : 1'b1;
			bramerr_out <= (bramerr_out == 1'b0) ? |bramerr_r : 1'b1;
			sb_ecc_out <= (sb_ecc_out == 1'b0) ? | sb_ecc_r : 1'b1;
		end		
	end
	
	assign luterr = luterr_out;
	assign bramerr = bramerr_out;
	assign sb_ecc = sb_ecc_out; 
	
	
	//connect to disassembler
	
	//synthesis translate_off
	disassembler gen_disasm(.gclk, .rst, .xcr, .dcache_replay(dcache2iu.replay));
  //synthesis translate_on	
	
  always_ff @(posedge gclk.clk) begin
      if (rst) begin
        pc_count    <= '0;
        count_state <= '0;
        error_led   <= '0;
      end
      else begin
        if (xcr.ts.run == 1 && xcr.ts.icmiss == 0 && ~(xcr.ts.replay | dcache2iu.replay) && count_state == 0)      //count excuted instructions (including annulled)
          pc_count <= pc_count + 1;      
      
        if ({xcr.ts.pc, 2'b0} == stopct_pc) 
          count_state <= '1;
        
        if ({xcr.ts.pc, 2'b0} == error_pc)
          error_led <= '1;
      end
   end 

  assign done_led = count_state;

endmodule

//synthesis translate_off
module sim_top;

parameter clkperiod = 2.5;

bit clk=0;
bit rst;
bit cpurst;

//IO interface
io_bus_out_type      io_in;
io_bus_in_type       io_out;

default clocking main_clk @(posedge clk);
endclocking

initial begin
  forever #clkperiod clk = ~clk;
end

initial begin

  rst 	 = '0;
  cpurst = '0;
  io_in.retry = '0;
  io_in.irl   = '0;
  io_in.rdata = '0;

//  ##10;
//  rst = '0;
  
  ##200;
  rst = '0;
  
  ##10;
  rst = '1;
  
  ##200;
  cpurst = '1;
  
  ##10;
  cpurst = '0;
end

fpga_top sim(.clkin_p(clk), 
            .clkin_n(~clk),
            .rstin(rst),
            .cpurst,
            .done_led(),
            .error_led() 
            );

endmodule
//synthesis translate_on
