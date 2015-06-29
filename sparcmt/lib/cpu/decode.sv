//------------------------------------------------------------------------------ 
// File:        decode.v
// Author:      Zhangxi Tan
// Description: decode functions and modules. used in decode stage
//------------------------------------------------------------------------------  

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libstd::*;
import libiu::*;
import libopcodes::*;
import libmmu::*;
import libcache::*;
import libtech::*;
`else
`include "libiu.sv"
`include "libmmu.sv"
`include "libcache.sv"
`endif

// evaluate integer branch instructions
task automatic iubranch(input decode_reg_type r, output bit branch_true, output bit annul);	
   /* bit	n = r.ts.psr.icc[3];
    bit z = r.ts.psr.icc[2];
    bit v = r.ts.psr.icc[1];
    bit c = r.ts.psr.icc[0];*/
    bit ticc;
`ifndef SYNP94
    bit	n = r.ts.psr.icc.N;
    bit z = r.ts.psr.icc.Z;
    bit v = r.ts.psr.icc.V;
    bit c = r.ts.psr.icc.C;
     
    bit branch = 0;
    bit ann = 0;

    bit [1:0] op  = r.ts.inst[31:30];
    bit [2:0] op2 = r.ts.inst[24:22];
    bit [5:0] op3 = r.ts.inst[24:19];
`else
    bit	n;
    bit z;
    bit v;
    bit c;
     
    bit branch;
    bit ann;

    bit [1:0] op;
    bit [2:0] op2;
    bit [5:0] op3;
    
    n = r.ts.psr.icc.N;
    z = r.ts.psr.icc.Z;
    v = r.ts.psr.icc.V;
    c = r.ts.psr.icc.C;
     
    branch = 0;
    ann = 0;

    op  = r.ts.inst[31:30];
    op2 = r.ts.inst[24:22];
    op3 = r.ts.inst[24:19];
`endif
    
    ticc = (op == FMT3 && op3 == TICC) ? '1 : '0;

    if ((op == FMT2 && op2 == BICC) || ticc) begin   //handle integer branch & TICC only now
      unique case (r.ts.inst[27:25])
      3'b000 : branch = r.ts.inst[28];				                // bn, ba
      3'b001 : branch = r.ts.inst[28] ^ z;      		        // be, bne
      3'b010 : branch = r.ts.inst[28] ^ (z | (n ^ v));    // ble, bg
      3'b011 : branch = r.ts.inst[28] ^ (n ^ v); 	        // bl, bge
      3'b100 : branch = r.ts.inst[28] ^ (c | z);   	      // bleu, bgu
      3'b101 : branch = r.ts.inst[28] ^ c;		              // bcs, bcc 
      3'b110 : branch = r.ts.inst[28] ^ n;		              // bneg, bpos
      3'b111 : branch = r.ts.inst[28] ^ v;		              // bvs, bvc   
      endcase
  
      if (branch == 1'b1) begin
      	if (r.ts.inst[29] == 1'b1 && r.ts.inst[28:25] == BA) //only annull BA
      		ann = '1;
  		  end
      else begin
	     if (r.ts.inst[29] == 1'b1)
		    ann = '1;	
		  end	  
    end
    
    branch_true = branch;
    annul = ann & !ticc;
endtask

// evaluate integer & fp branch instructions
task automatic iu_fpbranch(input decode_reg_type r, output bit branch_true, output bit annul);	
    bit ticc;
`ifndef SYNP94
    bit	n = r.ts.psr.icc.N;
    bit z = r.ts.psr.icc.Z;
    bit v = r.ts.psr.icc.V;
    bit c = r.ts.psr.icc.C;
    
    bit e = (r.ts.fsr.fcc == 2'b00);
    bit l = (r.ts.fsr.fcc == 2'b01);
    bit g = (r.ts.fsr.fcc == 2'b10);
    bit u = (r.ts.fsr.fcc == 2'b11);
     
    bit branch = 0;
    bit ann = 0;

    bit [1:0] op  = r.ts.inst[31:30];
    bit [2:0] op2 = r.ts.inst[24:22];
    bit [5:0] op3 = r.ts.inst[24:19];
`else
    bit	n;
    bit z;
    bit v;
    bit c;
    
    bit e;
    bit l;
    bit g;
    bit u;
   
    bit branch;
    bit ann;

    bit [1:0] op;
    bit [2:0] op2;
    bit [5:0] op3;
    
    n = r.ts.psr.icc.N;
    z = r.ts.psr.icc.Z;
    v = r.ts.psr.icc.V;
    c = r.ts.psr.icc.C;
    
    e = (r.ts.fsr.fcc == 2'b00);
    l = (r.ts.fsr.fcc == 2'b01);
    g = (r.ts.fsr.fcc == 2'b10);
    u = (r.ts.fsr.fcc == 2'b11);    
     
    branch = 0;
    ann = 0;

    op  = r.ts.inst[31:30];
    op2 = r.ts.inst[24:22];
    op3 = r.ts.inst[24:19];
`endif
    
    ticc = (op == FMT3 && op3 == TICC) ? '1 : '0;

    if ((op == FMT2 && op2 == BICC) || ticc) begin   //handle integer branch & TICC only now
      unique case (r.ts.inst[27:25])
      3'b000 : branch = r.ts.inst[28];				                // bn, ba
      3'b001 : branch = r.ts.inst[28] ^ z;      		        // be, bne
      3'b010 : branch = r.ts.inst[28] ^ (z | (n ^ v));    // ble, bg
      3'b011 : branch = r.ts.inst[28] ^ (n ^ v); 	        // bl, bge
      3'b100 : branch = r.ts.inst[28] ^ (c | z);   	      // bleu, bgu
      3'b101 : branch = r.ts.inst[28] ^ c;		              // bcs, bcc 
      3'b110 : branch = r.ts.inst[28] ^ n;		              // bneg, bpos
      3'b111 : branch = r.ts.inst[28] ^ v;		              // bvs, bvc   
      endcase
  
      if (branch == 1'b1) begin
      	if (r.ts.inst[29] == 1'b1 && r.ts.inst[28:25] == BA) //only annull BA
      		ann = '1;
  		  end
      else begin
	     if (r.ts.inst[29] == 1'b1)
		    ann = '1;	
		  end	  
    end
    
    if ((op == FMT2 && op2 == FBFCC)) begin               // floating point branches
      unique case (r.ts.inst[28:25])
      4'b1000: branch = '1;                               // fba
      4'b0000: branch = '0;                               // fbn
      4'b0111: branch = u;                                // fbu
      4'b0110: branch = g;                                // fbg
      4'b0101: branch = g | u;                            // fbug
      4'b0100: branch = l;                                // fbl
      4'b0011: branch = l | u;                            // fbul
      4'b0010: branch = l | g;                            // fblg
      4'b0001: branch = l | g | u;                        // fbne
      4'b1001: branch = e;                                // fbe
      4'b1010: branch = e | u;                            // fbue
      4'b1011: branch = e | g;                            // fbge
      4'b1100: branch = e | g | u;                        // fbuge
      4'b1101: branch = e | l;                            // fble
      4'b1110: branch = u | l | e;                        // fbule
      4'b1111: branch = e | l | g;                        // fbo 
      endcase
  
      if (branch == 1'b1) begin
      	if (r.ts.inst[29] == 1'b1 && r.ts.inst[28:25] == BA) //only annull FBA
      		ann = '1;
  		  end
      else begin
	     if (r.ts.inst[29] == 1'b1)
		    ann = '1;	
		  end	  
    end
    
    branch_true = branch;
    annul = ann & !ticc;
endtask

//cwp pointer control for RETT, RESTORE, SAVE, generate overflow, underflow exception
task automatic cwp_gen(input decode_reg_type r, output bit [NWINMSB:0] ncwp, output bit overflow, underflow);
`ifndef SYNP94
	bit [1:0] op  = r.ts.inst[31:30];
	bit [5:0] op3 = r.ts.inst[24:19];

	bit [NWINMSB:0]	new_cwp = r.ts.psr.cwp;
	bit ovrf = 0, undf = 0;

	bit [2**(NWINMSB+1)-1:0] win_mask = '0;
`else
	bit [1:0] op;
	bit [5:0] op3;

	bit [NWINMSB:0]	new_cwp;
	bit ovrf, undf;

	bit [2**(NWINMSB+1)-1:0] win_mask;
	
	op  = r.ts.inst[31:30];
	op3 = r.ts.inst[24:19];

	new_cwp = r.ts.psr.cwp;
	ovrf = 0; undf = 0;

	win_mask = '0;
`endif
	win_mask[NWIN-1:0] = r.ts.wim;

	if (op == FMT3) begin
		if (op3 == SAVE) begin
			new_cwp = (r.ts.psr.cwp == CWPMIN)? CWPMAX : r.ts.psr.cwp - 1;
			ovrf    = (win_mask[new_cwp] == 1'b1)? '1 : '0;
		end
		else if (op3 == RETT || op3 == RESTORE)	begin
			new_cwp = (r.ts.psr.cwp == CWPMAX)? CWPMIN : r.ts.psr.cwp + 1;
			undf    = (win_mask[new_cwp] == 1'b1)? '1 : '0;
		end
	end
	
	overflow  = ovrf;
	underflow = undf;
	
  ncwp = (ovrf | undf) ? r.ts.psr.cwp : new_cwp;
endtask


//generate rs2 BRAM address. Special handling include STD* instructions; load trap type; RDTBR (tt)
function automatic bit [NREGADDRMSB:0] rs2_gen(decode_reg_type r);
	bit [NREGADDRMSB:0] rs2addr;
`ifndef SYNP94
	bit [4:0] rs2 = r.ts.inst[4:0];
	bit [4:0] rd  = r.ts.inst[29:25];	

	bit [1:0] op  = r.ts.inst[31:30];
	bit [5:0] op3 = r.ts.inst[24:19];

	bit rs2mask   = r.rs2mask;
`else
	bit [4:0] rs2;
	bit [4:0] rd;	

	bit [1:0] op;
	bit [5:0] op3;

	bit rs2mask;
	
	rs2 = r.ts.inst[4:0];
	rd  = r.ts.inst[29:25];	

	op  = r.ts.inst[31:30];
	op3 = r.ts.inst[24:19];

	rs2mask   = r.rs2mask;
`endif	

	if (r.ts.ucmode == 1'b1) begin	//microcode access
		//ST only write back data in microcode mode. In the first cycle (normal mode), address will be calculated.
		//STD and ST are interpreted differently
    if (op == LDST && op3[3:0] == 7) begin		//STD*
      rs2mask = r.ts.rdmask;
			rs2 = {rd[4:1], 1'b1};	       //rd & 1'b11110 + 1,  for data
		end
		else if (op == LDST && (op3[3:0] >= 4 && op3[3:0] <= 6)) begin//ST 
      rs2mask = r.ts.rdmask;
			rs2 = rd;		//rd & 1'b11110,  for data		
		end
	end
	
	if (rs2mask == 1'b1)
		rs2addr = {r.ts.tid, REGADDRPAD0, rs2[2:0]};	//indirect to scratch pad register
	else
		rs2addr = regaddr(r.ts.tid, r.ts.psr.cwp, rs2);	

	return rs2addr;
endfunction

//generate rs1 BRAM address. Special handling include: SWAP, RDASR, RDTBR
function automatic bit [NREGADDRMSB:0] rs1_gen(decode_reg_type r);
	bit [NREGADDRMSB:0] rs1addr;
`ifndef SYNP94	
	bit [1:0] op  = r.ts.inst[31:30];
	bit [5:0] op3 = r.ts.inst[24:19];
	bit [4:0] rs1 = r.ts.inst[18:14];
`else
	bit [1:0] op;
	bit [5:0] op3;
	bit [4:0] rs1;

	op  = r.ts.inst[31:30];
	op3 = r.ts.inst[24:19];
	rs1 = r.ts.inst[18:14];
`endif	

	if	(op == FMT3 && op3 == RDTBR)			//read TBR
		rs1addr = {r.ts.tid, REGADDRPAD1, REGADDR_TBR};	//trap 		
	else if (r.rs1mask == 1'b1 || (op == FMT3 && op3 == RDY && ASREN == 1)) //RDASR or microcode
		rs1addr = {r.ts.tid, REGADDRPAD0, rs1[2:0]};
	else
		rs1addr = regaddr(r.ts.tid, r.ts.psr.cwp, rs1);
	
	return rs1addr;
endfunction

//generate rs1 BRAM address of fp regfile
function automatic bit [NFPREGADDRMSB:0] fp_rs1_gen(decode_reg_type r);
  bit [NFPREGADDRMSB:0] fprs1addr;
`ifndef SYNP94	
  bit [1:0] op  = r.ts.inst[31:30];
  bit [5:0] op3 = r.ts.inst[24:19];
  bit [4:0] rs1 = r.ts.inst[18:14];
  bit [4:0] rd  = r.ts.inst[29:25];
`else
  bit [1:0] op;
  bit [5:0] op3;
  bit [4:0] rs1;
  bit [4:0] rd;

  op  = r.ts.inst[31:30];
  op3 = r.ts.inst[24:19];
  rs1 = r.ts.inst[18:14];
  rd  = r.ts.inst[29:25];
`endif	

  if (op == LDST && (op3 == STF | op3 == STDF))
      fprs1addr = {r.ts.tid, rd};
  else
      fprs1addr = {r.ts.tid, rs1};

  return fprs1addr;
  
endfunction

//generate rs2 BRAM address of fp regfile
function automatic bit [NFPREGADDRMSB:0] fp_rs2_gen(decode_reg_type r);
  bit [NFPREGADDRMSB:0] fprs2addr;
`ifndef SYNP94	
  bit [1:0] op  = r.ts.inst[31:30];
  bit [5:0] op3 = r.ts.inst[24:19];
  bit [4:0] rs2 = r.ts.inst[4:0];
`else
  bit [1:0] op;
  bit [5:0] op3;
  bit [4:0] rs2;

  op  = r.ts.inst[31:30];
  op3 = r.ts.inst[24:19];
  rs2 = r.ts.inst[4:0];
`endif	

  fprs2addr = {r.ts.tid, rs2};

  return fprs2addr;
  
endfunction

//synthesize instruction from icache and microcode 
function automatic bit[31:0] gen_inst(decode_reg_type r);
`ifndef SYNP94
	bit [31:0] inst = r.ts.inst;
	bit [1:0]  op   = r.microinst[31:30];
	bit [2:0]  op2  = r.microinst[24:22];
	bit [5:0]  op3  = r.microinst[24:19];
`else
	bit [31:0] inst;
	bit [1:0]  op;
	bit [2:0]  op2;
	bit [5:0]  op3;

	inst = r.ts.inst;
	op   = r.microinst[31:30];
	op2  = r.microinst[24:22];
	op3  = r.microinst[24:19];
`endif	

	if (r.ts.ucmode) begin	
		//generate op
		inst[31:30] = op;
		//generate rd
		if (r.ts.rdmask | r.cwp_rd)
			inst[29:25] = r.microinst[29:25];	
		
		unique case(op)
		FMT2: inst = r.microinst;	
		FMT3, LDST : begin
  			           //generate op3
			           inst[24:19] = r.microinst[24:19];	
		             //generate i:asi
		             inst[13:5] = r.microinst[13:5];
		             //generate rs1
		             if (r.rs1mask | r.cwp_rs1)
  			             inst[18:14] = r.microinst[18:14];
		      	      //generate rs2
		      	      if (r.rs2mask | r.microinst[13])
			    	        inst[4:0] = r.microinst[4:0];	        //only inst[2:0] are used for 8 scratchpad registers			    	      
			    	        
		      end
		default: inst[24:0] = r.microinst[24:0];		//doesn't support CALL in microcode
		endcase	
	end
	
	return inst;
endfunction

task automatic decode_asi(input bit [31:0] inst, output bit ldst_a, output asi_type asi);
`ifndef SYNP94
  bit [1:0] op  = inst[31:30];
  bit [5:0] op3 = inst[24:19];	
`else
  bit [1:0] op;
  bit [5:0] op3;	

  op  = inst[31:30];
  op3 = inst[24:19];	
`endif  

  ldst_a = (op == LDST && op3[5:4] == 2'b01) ? '1 : '0;
  asi    = inst[5 +:5];      //only need 5 bits
endtask


module decode_stage(input iu_clk_type gclk, input bit rst, 
		input 	decode_reg_type 	   der, 
		input 	cache2iu_ctrl_type 	icache_de_out, 
		input 	immu_iu_out_type 	  immu2iu, 
		output reg_reg_type 	 	    regr /* synthesis syn_maxfan=16 */,
		output	bit			              luterr,
		output	bit			              bramerr,
		output	bit			              sb_ecc);
		
	bit [NWINMSB:0] ncwp;
	
	//pipeline register
	//reg_reg_type	   rr, rrin;
	reg_reg_type	   rrin;
	decode_reg_type	syr;	//synthesized register, patched in microcode mode

	//assign regr = rr;

	//always_comb begin
	always_comb begin
		syr = der;
		syr.ts.inst = gen_inst(der);		//patch inst

    //decode asi
    decode_asi(der.ts.inst, syr.ts.ldst_a, syr.ts.asi);
    
		rrin.rs1 = rs1_gen(syr);
		rrin.rs2 = rs2_gen(syr);		
		if (FPEN) begin
		  rrin.fprs1 = fp_rs1_gen(syr);
		  rrin.fprs2 = fp_rs2_gen(syr);
		end
		
		rrin.ts  = syr.ts;

		//cwp_gen(syr, ncwp, rrin.wovrf, rrin.wundf);
		//rrin.ts.psr.cwp[NWINMSB:0] = ncwp;
		
		if (FPEN)
		  iu_fpbranch(syr, rrin.branch_true, rrin.annul_next);	
		else
		  iubranch(syr, rrin.branch_true, rrin.annul_next);
		
		
		//handling icache/immu result
		rrin.ts.icmiss = icache_de_out.replay;
		rrin.ts.replay = (syr.ts.icmiss) ? icache_de_out.replay : syr.ts.replay | icache_de_out.replay;
		rrin.iaex      = immu2iu.data.exception;
		rrin.immu_data   = immu2iu.data;
		rrin.ts.run    = syr.ts.run & ~(icache_de_out.luterr | icache_de_out.bramerr) & ~(|immu2iu.parity_error);

		luterr  = icache_de_out.luterr;
		bramerr = icache_de_out.bramerr | (|immu2iu.parity_error);
		sb_ecc  = icache_de_out.sb_ecc;
	end


  function automatic reg_reg_type get_regr();
`ifndef SYNP94
    reg_reg_type  rr = rrin;
`else
	reg_reg_type  rr;
	rr = rrin;
`endif    
    
    if (rst == 1'b1) begin
    		rr.ts.run = '0;	
    end
      
  		if (icache_de_out.replay | immu2iu.data.exception) begin    //set inst to NOP on icache misses (synchronize set)
  		  rr.ts.inst     = 32'h01000000;
  		  rr.branch_true = '0;
  		  rr.annul_next  = '0;
  		end
    
    if (der.ts.run == 1'b0 && der.ts.dma_mode == 1'b0)
      rr.ts.inst = 32'h01000000;
      
    return rr;  
  endfunction

  //This is to prevent event race in modelsim
  always_ff @(posedge gclk.clk) begin
      regr <= get_regr();
  end

    
/*
	always @(posedge gclk.clk) begin		
	  regr = rrin;

		if (rst) begin
			regr.ts.run = '0;	
		end

		if (icache_de_out.replay) begin    //set inst to NOP on icache misses (synchronize set)
		  regr.ts.inst     = 32'h01000000;
		  regr.branch_true = '0;
		  regr.annul_next  = '0;
		end
	end
*/


endmodule