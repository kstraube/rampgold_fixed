//---------------------------------------------------------------------------   
// File:        simdma.sv
// Author:      Zhangxi Tan
// Description: Simulating a DMA master using BRAMs
//----------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libstd::*;
import libconf::*;
import libiu::*;
import libdebug::*;
import libopcodes::*;
import libcache::*;
import libtm::*;
`else
`include "../../../cpu/libiu.sv"
`include "../../../cpu/libmmu.sv"
`include "../../../cpu/libcache.sv"
`include "../../../tm/libtm.sv"
`endif


module dma_master(input iu_clk_type gclk, input bit rst,
				output  debug_dma_read_buffer_in_type   eth_rb_in,
				output  debug_dma_write_buffer_in_type  eth_wb_in,		//no use currently
				input 	 debug_dma_write_buffer_out_type eth_wb_out,		//no use currently				
				output  debug_dma_cmdif_in_type         dma_cmd_in,     //cmd input 
        input   bit                             dma_cmd_ack,    //cmd has been accepted                
        input 	 bit                             dma_done,		//dma status
        //timing model interface
        output  tm_dbg_ctrl_type                dma2tm,        
				//Init ROM interface
				output  bit	[15:0]						init_rom_addr,
				input   bit [31:0]						init_rom_data
				);
	typedef enum bit [2:0] {dm_idle, dm_init_mem, dm_dma_wait, dm_flush, dm_run, dm_stop} dma_master_state_type;
	
	dma_master_state_type	state, vstate;
	
	bit [12:0]				raddr, v_raddr, next_raddr, dly_raddr;
	bit           dly_we;
	bit						  wait_ack;	
	

	//bit [2:0] 				addr_msb, v_addr_msb;
	
	debug_dma_read_buffer_in_type	v_rb_in, r_rb_in;
	debug_dma_cmdif_in_type			    v_cmd_in;
	
	tm_dbg_ctrl_type              v_dma2tm;
	
	always_comb begin		
		v_raddr  = raddr;	
		vstate		 = state;	
		
		v_rb_in.addr = unsigned'(raddr);
		v_rb_in.we   = '0;
		v_rb_in.data = ldst_big_endian(init_rom_data);
		v_rb_in.inst = {LDST, 5'b0, ST, 5'b0, 1'b1, 13'b0 };
		
		v_cmd_in.tid           = '0;		//single thread no
		v_cmd_in.addr_reg.addr = unsigned'({raddr[12:10], 10'b0});        //target virtual address		
		v_cmd_in.addr_we       = '0;
		
		v_cmd_in.ctrl_reg.buf_addr = '0;
		v_cmd_in.ctrl_reg.count    = '1;		//full count
		v_cmd_in.ctrl_reg.cmd	     = dma_OP;	//default command
		v_cmd_in.ctrl_we           = '0;				
		
		v_dma2tm   = tm_dbg_nop;
		
		next_raddr = raddr + 1;				//address counter
		wait_ack   = '0;
		
		unique case (state)
		dm_idle		: vstate = dm_init_mem;
		dm_init_mem	: begin
						v_raddr    = next_raddr;
						v_rb_in.we = '1;
						
						//v_addr_msb = raddr[12:10];
						
						if (raddr[9:0] == 10'b1111111111) begin							
							v_cmd_in.addr_we = '1;													
							
							if (dma_cmd_ack) begin
								vstate = dm_dma_wait;
								v_rb_in.we = '0;
							end
							else begin
								wait_ack = '1;			//keep command valid till it is accepted				
														
                v_cmd_in.ctrl_we = '1;

							end
						end
					end		
		dm_dma_wait : begin
						if (dma_done) begin
							if (raddr[12:10] == 3'b0)  begin
								vstate  = dm_flush;
								v_raddr = '0;
							end
							else
								vstate = dm_init_mem;
						end
					end
		dm_flush : begin
					v_raddr = next_raddr;					
					v_rb_in.we   = '1;
					v_rb_in.data[DCACHEINDEXMSB_MEM:DCACHEINDEXLSB_MEM] = raddr[0 +: 3];      
					v_rb_in.inst = {FMT3, 5'b0, FLUSH, 5'b0, 1'b1, 13'b0 };
					
					v_cmd_in.ctrl_reg.count = 7;
					
					if (raddr[2:0] == 3'b111) begin
						
						if (dma_cmd_ack) begin						  
							vstate     = dm_run;
							v_rb_in.we = '0;
						end
						else begin
							wait_ack = '1;
						  v_cmd_in.ctrl_we = '1;
						end
					end
				 end
		dm_run: begin
		      if (dma_done) begin
              v_dma2tm = tm_dbg_start;              
          				vstate = dm_stop;
    				  end
				end
		dm_stop: ;			//does nothing
		endcase
		
		v_cmd_in.addr_reg.parity = (LUTRAMPROT) ? ^v_cmd_in.addr_reg.addr : '0;
		v_cmd_in.ctrl_reg.parity = ^{v_cmd_in.ctrl_reg.buf_addr, v_cmd_in.ctrl_reg.count, v_cmd_in.ctrl_reg.cmd};
		
		
		init_rom_addr = {1'b1, raddr, 2'b11};		//Init ROM addr								
		
		//output		
		eth_rb_in      = r_rb_in;     //default

    if (state!=dm_flush) begin    //override the default
    		eth_rb_in.addr = dly_raddr;   
    		eth_rb_in.we   = dly_we;
		end
	end
	
	
	always_ff @(posedge gclk.clk) begin
		if (rst) state <= dm_idle; else state <= vstate;		
		
		if (rst) dma2tm <= tm_dbg_nop; else dma2tm <= v_dma2tm;
    
    r_rb_in  <= v_rb_in;
    
    //pipeline register to balance ROM read timing
    dly_raddr <= r_rb_in.addr;
    dly_we    <= r_rb_in.we;
    
    //outputs
    dma_cmd_in <= v_cmd_in;
		
    if (rst) 
      raddr <= '0;
		else if (!wait_ack)
			raddr <= v_raddr;		
	end		
endmodule
