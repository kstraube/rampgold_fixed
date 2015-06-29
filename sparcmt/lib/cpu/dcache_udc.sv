//------------------------------------------------------------------------------------------
// File:        dcache.v
// Author:      Zhangxi Tan & Yunsup Lee
// Description: D$ implemenation. Currently, direct-map, write-back, write-allocate $.  
//		32-byte block size (same as BEE3 memory burst). 8-block (256B), split I/D
//------------------------------------------------------------------------------------------

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libcache::*;
import libmmu::*;
import libmemif::*;
import libstd::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`include "../mem/libmemif.sv"
`endif

function bit [31:0] get_modify_data(bit [31:0] read_data, bit [31:0] modify_data, bit [3:0] byte_mask);
	bit [31:0] res;

 	res[31:24] = (byte_mask[3])? modify_data[7:0]     : read_data[31:24];
 	res[23:16] = (byte_mask[2])? modify_data[15:8]    : read_data[23:16];
 	res[15:8]  = (byte_mask[1])? modify_data[23:16]   : read_data[15:8];
 	res[7:0]   = (byte_mask[0])? modify_data[31:24]   : read_data[7:0];
	 
	return res;
endfunction  

//can't recover tag SEU from dtag, because it might be dirty

//module dcache #(parameter int CACHEDATAPROT = 2, parameter int AUTORECOVER = 0)	//protect with ECC 
module dcache_udc #(parameter CACHEDATAPROT = 2, parameter AUTORECOVER = 0, parameter read2x = 0, parameter write2x = 0)	//protect with ECC 
	(input iu_clk_type gclk, input bit rst,	 
	      //-------------memory interface----------------
	      input  mem_stat_out_type		  mem2iu_stat,	//memory status output
	      output bit [NTHREADIDMSB:0]	iu2mem_tid,	 //request valid bit read back
	      output mem_cmd_in_type		    iu2mem_cmd,	 //memory command
	      //-------------cache ram interface----------------
	      input  cache_ram_in_type		  mem2cacheram,//mem -> cache ram
	      output cache_ram_out_type		 cacheram2mem,//cache ram -> mem
	      //-------------pipeline & MMU interface----------------
	      input  dcache_iu_in_type		  iu2cache,	   //input from IU
	      input  dcache_mmu_in_type		 dmmu2cache, 	//input from MMU	

	      output dcache_data_out_type	data_out,	   //64-bit cache data output to IU 
		   //output bit[63:0]				data_out,
	      output cache2iu_ctrl_type 	 dcache2iu	   //replay control to IU (xc stage) 
	      
//	      output cache_error_type		parity_error	//parity errors
 );
	//cache ram <-> IU interface
	cache_ram_out_type		cacheram2iu;		//cache ram -> IU
	cache_ram_in_type		 iu2cacheram;		//IU -> cache ram	

	cache_tag_type			new_dtag;		//wires: new dtag

  bit busy, busy_r;
  bit [NTHREADIDMSB:0] busy_tid, busy_tid_r;
  bit whit_rr, whit_r, whit;
  bit [8:0] whit_idx_rr, whit_idx_r, whit_idx, xcr_idx, busy_idx_r, busy_idx;
  bit busy_cache_hit;

	bit				cache_hit;		 //is cache hit
	bit     mem_ops;     //is memory ops
	bit				tag_parity;		//dcache parity decoding
	
	bit [63:0]			read_data;		             //wires, used as read/modify (read phase)
	bit [DCACHELINEMSB_IU:0]	write_data;		//wires, used as read/modify (write phase)

	bit 				we_tag;			           //variable for we_tag
	bit [DCSIZE-1:0]		we_data ;		//variable for we_data
	//--------------pipeline registers--------------			
	typedef struct {
		bit [DTLBTAGLSB-1:DCACHETAGLSB]	tag_offset;	//offset used to calculate physical cache tag (difference between tlb tag & cache tag)
		bit [2:0]			                    word_sel;	  //bit used to generate we_data
		bit [63:0]			                   read_data;	 //used for read/modify	
		bit [31:0]			                   store_data;
		bit [3:0]			                    byte_mask; 		 			
//		LDST_CTRL_TYPE			               ldst;		     //ld/st
    bit [$bits(LDST_CTRL_TYPE)-1:0]	ldst;		     //ld/st
    bit                             swap;
		bit                             dma_mode;   //flush in dma mode (flush $ blocks based on idx not virtual address)
		cache_ram_read_in_type		        req;		      //read request, contains tid & line index
		cache_tag_type			               dc_tag;		   //readout old tag
		cache_data_error_type	          dc_data_ecc;//data ecc
		//pipeline status
		bit				                        valid;		    //lookup is valid
		bit				                        tid_parity;		
    bit [NTHREADIDMSB:0]              tid;
	}delr_xc_type;		//ex register type
			
	(* syn_preserve = 1*) delr_xc_type		delr_xc;
		
	//flush support
	bit  isflush;

  //coverage
  //synthesis translate_off
  cache_stat_type                 hit_or_miss;  
  //synthesis translate_on
  
	
	//--------------mem if & pipeline control------------------
	mem_cmd_in_type		mem_cmd;
 	bit			          new_replay;
	//--------------IU interface------------------
	//read tag & data,	1st cycle in mem
	//assign iu2cacheram.read.tid = iu2cache.m1.tid;							//threadid
	assign iu2cacheram.read.tid = iu2cache.m1.va[13:8];							//threadid
	assign iu2cacheram.read.index.D = iu2cache.m1.va[DCACHEINDEXMSB_IU:DCACHEINDEXLSB_IU];	//index
		
  assign xcr_idx = {delr_xc.req.tid, delr_xc.req.index.D[DCACHEINDEXMSB_MEM:DCACHEINDEXLSB_MEM]};

	//assign parity_error.data_ecc_err = cacheram2iu.data.ecc_error;	
	//assign parity_error.tag_parity =  tag_parity; 	
	
	//-------------request to read out busy bit of  mem if---------------
	//assign iu2mem_tid = iu2cache.m2.tid;
	assign iu2mem_tid = iu2cache.m2.va[13:8];

	//2nd cycle in mem	
	always_comb begin
		//The following 64-bit 4-1, must be completed at ~400 MHz (2.5ns)		 		 	
		unique case(iu2cache.m2.va[3:2])
		2'b00: data_out[31:0] = ldst_big_endian(cacheram2iu.data.data.D[31:0]);						
		2'b01: data_out[31:0] = ldst_big_endian(cacheram2iu.data.data.D[63:32]);
		2'b10: data_out[31:0] = ldst_big_endian(cacheram2iu.data.data.D[95:64]);
		2'b11: data_out[31:0] = ldst_big_endian(cacheram2iu.data.data.D[127:96]);
		endcase		

		unique case(iu2cache.m2.va[3])
		1'b0: begin 
        			data_out[63:32] = ldst_big_endian(cacheram2iu.data.data.D[63:32]);
        			read_data       = cacheram2iu.data.data.D[63:0];
		      end
		1'b1: begin
        			data_out[63:32] = ldst_big_endian(cacheram2iu.data.data.D[127:96]);
        			read_data       = cacheram2iu.data.data.D[127:64];
		      end
		endcase		 		
	end 

	//exception cycle
  always_comb begin
		//initial values
		we_tag     = '0;
		tag_parity = '0;
		write_data = '0;
		we_data    = '0;
    busy       = '0;
    busy_tid   = '0;
    whit       = '0;
    whit_idx   = '0;
    busy_cache_hit = '0;
    busy_idx   = '0;

		//----------generate cache/tlb op------------
		//read & modify data		
		unique case(delr_xc.word_sel[0])
		1'b0: write_data[63:0] = {delr_xc.read_data[63:32], get_modify_data(delr_xc.read_data[31:0], delr_xc.store_data, delr_xc.byte_mask)};
		1'b1: write_data[63:0] = {get_modify_data(delr_xc.read_data[63:32], delr_xc.store_data, delr_xc.byte_mask), delr_xc.read_data[31:0]};
		endcase 
		iu2cacheram.write.data.data.D = write_data; 			//only the least 64 bits are used	

		if (!AUTORECOVER && BRAMPROT>0)					           //automatically recover from tag SEU
			tag_parity = ^delr_xc.dc_tag;

    mem_ops  = (delr_xc.ldst != NOMEM)? '1 : '0;
    isflush   = (delr_xc.ldst == c_FLUSH)? '1 : '0;
									
		//mem cmd initial values
		mem_cmd.tid         = delr_xc.req.tid;
		mem_cmd.tid_parity  = delr_xc.tid_parity;
		mem_cmd.cmd.D       = DCACHE_LD; 
		mem_cmd.valid       = delr_xc.valid & dmmu2cache.valid & ~mem2iu_stat.busy;
		mem_cmd.ret_index.D = delr_xc.req.index.D[DCACHEINDEXMSB_MEM:DCACHEINDEXLSB_MEM];
		//cache write input		
	
		new_dtag.tag.D = {dmmu2cache.paddr, delr_xc.tag_offset};	//new phsyical tag
		new_dtag.valid = '1;						                         //tag valid bit, if write				
		new_dtag.dirty = '0;
		//cache write control signal
		iu2cacheram.write.index.D = delr_xc.req.index.D;			//same as read
		iu2cacheram.write.tid     = delr_xc.req.tid;			    //same as read
		
	 
		//write tag & data				
		cache_hit = (delr_xc.dc_tag.tag.D == new_dtag.tag.D)? delr_xc.dc_tag.valid : '0; //treat non-mem ops as cache hit 								

		//iu output	
		new_replay =  mem2iu_stat.busy & delr_xc.valid;		
		
		//main d$ FSM
    if (!mem2iu_stat.busy)  begin				//first access attempt or last acccess is completed
      if (!dmmu2cache.tlb_hit)	begin		//tlb miss	
        mem_cmd.cmd.D = dmmu2cache.rtype;		//tlb request: dmmu_walk, dtlb_write
        new_replay    = dmmu2cache.valid;
      end
      else if (dmmu2cache.exception) begin		//DAEX
        mem_cmd.valid = '0;
        new_replay    = '0;
      end
      else if	(!cache_hit || isflush) begin			//cache miss or flush, store will always hit (2nd cycle)
        we_data    = '0;
        new_replay = delr_xc.valid;
        
        if (!delr_xc.dc_tag.valid || (delr_xc.dc_tag.valid && !delr_xc.dc_tag.dirty)) begin	//clean miss
          mem_cmd.cmd.D = DCACHE_LD;	//load & write new tag
          we_tag        = delr_xc.valid;
          
          if (isflush) begin
            mem_cmd.valid = '0;
            
           //we_tag     = '0;
          end
        end
        else begin	//dirty miss, write back
          mem_cmd.cmd.D  = DCACHE_WB;	     //first write back
          we_tag         = delr_xc.valid;  
          new_dtag       = delr_xc.dc_tag;	//use the old tag, but clear the dirty bit
          new_dtag.dirty = '0;
          
          if (isflush) begin
            //new_replay    = new_replay & cache_hit;
              mem_cmd.valid = mem_cmd.valid & (cache_hit | delr_xc.dma_mode);
          end
        end  
        
        if (isflush) begin
            we_tag         = we_tag & (cache_hit | delr_xc.dma_mode);
            new_dtag.valid = '0;
            new_replay     = '0;    //write back will always happen in non-ucmode for flush
        end
      end
      else begin					//cache hit
        // swap should be atomic
        if (delr_xc.atomic == 1'b0)
          busy_cache_hit = '1;

        if (delr_xc.ldst[0]) begin		//write hit
          new_dtag.dirty = '1;
          whit = 1'b1;
          whit_idx = xcr_idx;
          if (delr_xc.valid) begin	//update dcache
            we_tag = '1;
            unique case (delr_xc.word_sel[2:1])
            2'b00 :	we_data = 4'b0001;
            2'b01 : we_data = 4'b0010;
            2'b10 : we_data = 4'b0100;
            2'b11 : we_data = 4'b1000;
            endcase
          end 
        end

        mem_cmd.valid = '0;			//this is perfect, nothing is miss
        new_replay    = '0;
      end

      if (whit_r == 1'b1 && whit_idx_r == xcr_idx || whit_rr == 1'b1 && whit_idx_rr == xcr_idx) begin
        we_tag = '0;
        we_data = 4'b0000;
        new_replay = delr_xc.valid;
        mem_cmd.valid = '0;
        whit = '0;
        whit_idx = '0;
      end

      if (busy_cache_hit == 1'b1 && busy_r == 1'b1 && busy_idx_r == xcr_idx) begin
        if (busy_tid_r != delr_xc.tid) begin
          we_tag = '0;
          we_data = 4'b0000;
          new_replay = delr_xc.valid;
          mem_cmd.valid = '0;
        end
        busy_cache_hit = '0;
      end

      busy = mem_cmd.valid & mem_ops | delr_xc.atomic | (isflush & (~delr_xc.dma_mode | mem_cmd.valid));
      busy_tid = delr_xc.tid;

      // if microcode mode, there are some possibilties that the instructino
      // itself is not a memory operation.  in this case, we loose xcr_idx
      if (delr_xc.atomic == 1'b1 && busy_r == 1'b1)
        busy_idx = busy_idx_r;
      else
        busy_idx = xcr_idx;

    end

    if (busy_r == 1'b1 && (busy_tid_r != delr_xc.tid || mem2iu_stat.busy == 1'b1)) begin
      busy = busy_r;
      busy_tid = busy_tid_r;
      busy_idx = busy_idx_r;
      mem_cmd.valid = '0;
      if (busy_cache_hit == 1'b0) begin
        new_replay = delr_xc.valid;
        we_tag = '0;
        we_data = 4'b0000;
        whit = '0;
        whit_idx = '0;
      end
    end
		
		//new_dtag.dirty = iu2cache.m2.ldst[0];				//if store then dirty	
		//incremental tag parity generation		
		new_dtag.parity = (BRAMPROT > 0)? ^new_dtag.tag.D ^ new_dtag.valid ^new_dtag.dirty: '0;

		iu2cacheram.write.tag     = new_dtag;
    mem_cmd.valid             = mem_cmd.valid & mem_ops;
		iu2mem_cmd                = mem_cmd;
		iu2cacheram.write.we_tag  = we_tag & mem_ops;		
		iu2cacheram.write.we_data = we_data & {DCSIZE{mem_ops}};

		dcache2iu.replay  = new_replay & mem_ops;		
		dcache2iu.luterr  = (LUTRAMPROT)? (mem2iu_stat.busy ^ mem2iu_stat.parity) : '0;
		dcache2iu.bramerr = tag_parity | delr_xc.dc_data_ecc.dberr;	//can't recover double bit errors
		dcache2iu.sb_ecc  = delr_xc.dc_data_ecc.sberr;
		
	end
		
  //synthesis translate_off
  always_ff @(posedge gclk.clk) begin
     if (mem_cmd.valid) begin
        unique case(mem_cmd.cmd.D)
          //DCACHE_LD : $display("@%t: D$ issues a mem LD request from $line %d of thread %d", $time, mem_cmd.ret_index.D, mem_cmd.tid);
          //DCACHE_WB : $display("@%t: D$ issues a mem WB request from $line %d of thread %d", $time, mem_cmd.ret_index.D, mem_cmd.tid);
          DCACHE_LD : $display("@%t: D$ issues a mem LD request from $line %d", $time, mem_cmd.ret_index.D+mem_cmd.tid*8);
          DCACHE_WB : $display("@%t: D$ issues a mem WB request from $line %d", $time, mem_cmd.ret_index.D+mem_cmd.tid*8);
        endcase
     end
  end
  
  always_comb begin
    hit_or_miss = nop;
    if (~isflush & ~mem2iu_stat.busy & mem_ops & delr_xc.valid) begin
      if (mem_cmd.valid &&  mem_cmd.cmd.D == DCACHE_LD)
        hit_or_miss = miss;
      else if (cache_hit) 
        hit_or_miss = hit;     //this includes the hit after a miss.
    end    
  end
  
  covergroup cg_dc_hitmiss @(posedge gclk.clk);
     coverpoint hit_or_miss iff (!rst && !delr_xc.dma_mode);
  endgroup
  
  cg_dc_hitmiss dc_stat = new;
  //synthesis translate_on    
		
	//mem-exception pipeline register
	always_ff @(posedge gclk.clk) begin
		//cache ram request 'address'
		//delr_xc.req.tid     <= iu2cache.m2.tid;
		delr_xc.req.tid     <= iu2cache.m2.va[13:8];
    delr_xc.tid         <= iu2cache.m2.tid;
		delr_xc.tid_parity  <= iu2cache.m2.tid_parity;		
	 	delr_xc.req.index.D <=	iu2cache.m2.va[DCACHEINDEXMSB_IU:DCACHEINDEXLSB_IU];				

		delr_xc.tag_offset  <= iu2cache.m2.va[DTLBTAGLSB-1:DCACHETAGLSB];	//for generating physical tag		

		//output from dcache ram (clk2x)
		delr_xc.dc_tag  <= cacheram2iu.tag;		
		
		delr_xc.read_data  <= read_data;
		delr_xc.word_sel   <= iu2cache.m2.va[4:2];
		delr_xc.byte_mask  <= iu2cache.m2.byte_mask;
		delr_xc.store_data <= iu2cache.m2.store_data;
		delr_xc.ldst       <= iu2cache.m2.ldst;
    delr_xc.atomic       <= iu2cache.m2.atomic;
    delr_xc.dma_mode  <= iu2cache.m2.dma_mode;
		//forward pipeline control
		delr_xc.valid  <= iu2cache.m2.valid;
		//delr_xc.replay <= iu2cache.m2.replay;  
	end
	
	//we need to capture ecc error at 2x
	always_ff @(posedge gclk.clk2x) begin
		delr_xc.dc_data_ecc <= cacheram2iu.data.ecc_error;
	end

  always_ff @(posedge gclk.clk) begin
    if (rst == 1'b1) begin
      busy_r <= 1'b0;
      busy_tid_r <= 6'b111111;
      busy_idx_r <= 9'b111111111;
      whit_r <= 1'b0;
      whit_rr <= 1'b0;
      whit_idx_r <= 9'b111111111;
      whit_idx_rr <= 9'b111111111;
    end
    else begin
      busy_r <= busy;
      busy_tid_r <= busy_tid;
      busy_idx_r <= busy_idx;
      whit_r <= whit;
      whit_rr <= whit_r;
      whit_idx_r <= whit_idx;
      whit_idx_rr <= whit_idx_r;
    end
  end

	dcache_ram #(.tagprot(BRAMPROT), .read2x(read2x), .write2x(write2x))		//tags are protected with parity
	dc_bram	(
	 .gclk,
	 .rst,
	 .iu_in(iu2cacheram),		//iu read/write
	 .iu_out(cacheram2iu),
	 .mem_in(mem2cacheram),		//mem read/write
	 .mem_out(cacheram2mem)	 
	);

endmodule
