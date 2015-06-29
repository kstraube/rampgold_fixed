//------------------------------------------------------------------------------------------
// File:        icache.v
// Author:      Zhangxi Tan
// Description: I$ implemenation. Currently, direct-map, write-back, write-allocate $.  
//		32-byte block size (same as BEE3 memory burst). 8-block (256B), split I/D
//------------------------------------------------------------------------------------------

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libcache::*;
import libmemif::*;
import libmmu::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`include "../mem/libmemif.sv"
`endif

//todo add mem control
//module icache #(parameter int AUTORECOVER = 0,
//	 parameter int CACHEDATAPROT = 2,	//protect with ECC
//	 parameter NONECCDRAM = "TRUE")		//non-ECC dram	 
module icache #(parameter AUTORECOVER = 0,
	 parameter CACHEDATAPROT = 2,	//protect with ECC
	 parameter read2x  = 0,
	 parameter write2x = 0,
	 parameter NONECCDRAM = "FALSE")		//non-ECC dram	 

	(input iu_clk_type gclk, input bit rst,	 
	      //-------------memory interface----------------
	      input mem_stat_out_type		mem2iu_stat,	//memory status output
	      output bit [NTHREADIDMSB:0]	iu2mem_tid,	//request busy bit read back
	      output mem_cmd_in_type		iu2mem_cmd,	//memory command
	      //-------------cache ram interface----------------
	      input cache_ram_in_type		mem2cacheram,	//mem -> cache ram
	      output cache_ram_out_type		cacheram2mem,	//cache ram -> mem
	      //-------------pipeline & MMU interface----------------
	      input icache_if_in_type		iu2cache,	//first cycle input (read)
	      input icache_de_in_type		immu2cache, 	//second cycle input (write) from MMU	

		  //debug 
		  //output bit [127:0]			cacheram_dbg_out,
		  //output bit [8:0]				cacheram_read_addr,
		  //end of debug
	      output icache_data_out_type		if_out,		//cache ram output to IU in fetch stage
	      output cache2iu_ctrl_type 	de_out		//output to pipeline in decode stage
//	      output cache_error_type		parity_error	//parity errors
 );
	//cache ram <-> IU interface
	cache_ram_out_type		cacheram2iu;	//cache ram -> IU
	cache_ram_in_type		 iu2cacheram;	//IU -> cache ram	

	cache_tag_type			new_itag;	//wires: new itag
	bit				         we_tag;	  //variable for we_tag

	bit				cache_hit;	 //is cache hit
	bit				tag_parity;	//icache parity decoding	
	//--------------pipeline registers--------------		
	typedef struct {
		cache_ram_read_in_type		req;		//read request (tid, cache index)
		bit [1:0]			wmask;		//used to select correct word from cache line		
		bit [ITLBINDEXLSB-1:ICACHETAGLSB]	tag_offset;	//offset used to calculate cache tag
		//pipeline status
		bit				valid;		//lookup is valid
		bit				replay;		//replay mode

		bit				tid_parity; 	//used to	
	}delr_if_type; 		//if register type

	typedef struct {
		bit [ITLBINDEXLSB-1:ICACHETAGLSB]	tag_offset;	//offset used to calculate cache tag		
		cache_ram_read_in_type		req;		//read request, contains tid & line index
		cache_tag_type			ic_tag;
		cache_data_error_type		ic_data_ecc;	//data ecc
		//pipeline status
		bit				valid;		//lookup is valid
		bit				replay;		//replay mode

		bit				tid_parity; 	//used to protect lutram		
	}delr_de_type;		//de register type
	
	delr_if_type		delr_if;
	delr_de_type		delr_de;
	//--------------mem if & pipeline control------------------
	mem_cmd_in_type		mem_cmd;			//mem_cmd
 	bit			new_replay;
 		
 	//coverage statistics for cache hit/miss
  //synthesis translate_off
  cache_stat_type                 hit_or_miss;  
  //synthesis translate_on

	//--------------IU interface------------------
	//read tag & data,	1st IF cycle
	assign iu2cacheram.read.tid = iu2cache.tid;						//threadid
	assign iu2cacheram.read.index.I = iu2cache.vpc[ICACHEINDEXMSB_IU:ICACHEINDEXLSB_IU];	//index
	
	//assign parity_error.data_ecc_error = cacheram2iu.data.ecc_err;	
	//assign parity_error.tag_parity =  tag_parity; 	
	
	//-------------request to read out busy bit of  mem if---------------
	assign iu2mem_tid = delr_if.req.tid; 

	//2nd IF cycle
	always_comb begin
		//need cross module optimization here!
		//The following 64-bit 4-1, must be completed at ~400 MHz (2.5ns)		 
		//if_out is valid in the 2nd half of the last IF cycle 	
		unique case(delr_if.wmask[1:0])
		2'b00: if_out = cacheram2iu.data.data.I[31:0];
		2'b01: if_out = cacheram2iu.data.data.I[63:32];
		2'b10: if_out = cacheram2iu.data.data.I[95:64];
		2'b11: if_out = cacheram2iu.data.data.I[127:96];
		endcase			
	end
	
	//dbg_out
	//always_ff @(posedge gclk.clk) begin 
	//	cacheram_dbg_out <= cacheram2iu.data.data.I;
	//	cacheram_read_addr <= {iu2cache.tid, iu2cache.vpc[ICACHEINDEXMSB_MEM:ICACHEINDEXLSB_MEM]};
	//end
	
	//decode cycle
	//always_comb begin
	always_comb begin
		//initial values
		we_tag     = '0;				
		tag_parity = '0;

		if (!AUTORECOVER && BRAMPROT>0)					//automatically recover from tag SEU		
			tag_parity = ^delr_de.ic_tag;		

		//----------generate cache/tlb op in decoding stage------------
					
		//mem cmd initial values
		mem_cmd.tid         = delr_de.req.tid;
		mem_cmd.tid_parity  = delr_de.tid_parity;
		mem_cmd.cmd.I       = ICACHE_LD; 
		mem_cmd.valid       = delr_de.valid & immu2cache.valid & ~mem2iu_stat.busy;
		mem_cmd.ret_index.I = delr_de.req.index.I[ICACHEINDEXMSB_MEM:ICACHEINDEXLSB_MEM];

		//cache write input		
		new_itag.tag.I = {immu2cache.paddr, delr_de.tag_offset};	//new phsyical tag
		new_itag.valid = ~immu2cache.iflush;						               //valid bit
		new_itag.dirty = '0;						//never write back for I$	
		//incremental tag parity generation
		new_itag.parity = (BRAMPROT > 0)? ^new_itag.tag.I ^ new_itag.valid : '0;
		iu2cacheram.write.tag = new_itag;

		//cache write control signal
		iu2cacheram.write.index.I   = (immu2cache.iflush)? {immu2cache.flushidx, 1'b0} : delr_de.req.index.I;			//same as read
		iu2cacheram.write.tid       = delr_de.req.tid;			//same as read
		iu2cacheram.write.we_data.I = '0;				//iu never write to icache data but tag
		//write tag & data				
		cache_hit = (delr_de.ic_tag.tag.I == new_itag.tag.I)? delr_de.ic_tag.valid : '0; //if we have enough DSPs.... 
		cache_hit = cache_hit | immu2cache.iflush;	
		if (AUTORECOVER  && BRAMPROT>0)					//automatically recover from tag SEU
			cache_hit = cache_hit & !tag_parity;			

		//iu output
		new_replay =  mem2iu_stat.busy & delr_de.valid;
		
		
		if (!mem2iu_stat.busy)  begin				//first access attempt or last acccess is completed
			if (!immu2cache.tlb_hit)	begin 		//tlb miss			
//				mem_cmd.cmd.I = immu2cache.rtype;		//tlb request: immu_walk, itlb_write
  		mem_cmd.valid = '0;
	      new_replay    = immu2cache.valid;
			end
			else if (immu2cache.exception) begin		//tlb exceptions, stop fetch
				mem_cmd.valid = '0;			//this is perfect, nothing is miss
				new_replay    =  '0;
			end
			else if	(!cache_hit) begin
				mem_cmd.cmd.I = ICACHE_LD;
				we_tag        = delr_de.valid ;				//update tag: line is valid
				new_replay    = delr_de.valid;
			end
			else begin
				mem_cmd.valid = '0;			//this is perfect, nothing is miss
				new_replay    = '0;
			end
		end
		
		iu2cacheram.write.we_tag = we_tag | immu2cache.iflush;
    mem_cmd.valid            = ~immu2cache.iflush & mem_cmd.valid;
		iu2mem_cmd               = mem_cmd;

		de_out.replay = new_replay;		
		
		de_out.luterr  = (LUTRAMPROT)? (mem2iu_stat.busy ^ mem2iu_stat.parity) : '0;
		de_out.bramerr = tag_parity | delr_de.ic_data_ecc.dberr;
		de_out.sb_ecc  = delr_de.ic_data_ecc.sberr;
		
	//synthesis translate_off
  //  if (mem_cmd.valid) 
  //   $display("@%t: I$ issues a mem request ", $time);
	//synthesis translate_on
	end

  //synthesis translate_off
  always_ff @(posedge gclk.clk) begin
     if (mem_cmd.valid) begin
         $display("@%t: I$ issues a mem request from $line %d of thread %d", $time, mem_cmd.ret_index.I, mem_cmd.tid);       
     end
  end
  
  always_comb begin
    hit_or_miss = nop;
    if (~immu2cache.iflush & ~mem2iu_stat.busy & delr_de.valid) begin
      if (mem_cmd.valid &&  mem_cmd.cmd.I == ICACHE_LD)
        hit_or_miss = miss;
      else if (cache_hit) 
        hit_or_miss = hit;     //this includes the hit after a miss.
    end    
  end
  
  covergroup cg_ic_hitmiss @(posedge gclk.clk);
     coverpoint hit_or_miss iff (!rst);
  endgroup
  
  cg_ic_hitmiss ic_stat = new;

  //synthesis translate_on    

	always_ff @(posedge gclk.clk) begin
		//IF pipeline register
		delr_if.req        <= iu2cacheram.read;
		delr_if.wmask      <= iu2cache.vpc[3:2];
		delr_if.tag_offset <= iu2cache.vpc[ITLBINDEXLSB-1:ICACHETAGLSB];
		delr_if.valid      <= iu2cache.valid;
		delr_if.replay     <= iu2cache.replay;		//this is a redundant register. either better timing or shared by synthesis 
		delr_if.tid_parity <= iu2cache.tid_parity;
		
		
		delr_de.req        <= delr_if.req;
		delr_de.tag_offset <= delr_if.tag_offset;
		//output from icache ram (clk2x) 
		delr_de.ic_tag     <= cacheram2iu.tag;
		delr_de.valid      <= delr_if.valid;			    //valid request
		delr_de.replay     <= delr_if.replay;	

	end
	
	always_ff @(posedge gclk.clk2x) begin
		delr_de.ic_data_ecc <= cacheram2iu.data.ecc_error;
	end

	icache_ram #(.tagprot(BRAMPROT), .read2x(read2x), .write2x(write2x))		//tags are protected with parity
	ic_bram	(
	 .gclk,
	 .rst,
	 .iu_in(iu2cacheram),		//iu read/write
	 .iu_out(cacheram2iu),
	 .mem_in(mem2cacheram),		//mem read/write
	 .mem_out(cacheram2mem)	 
	);

endmodule
