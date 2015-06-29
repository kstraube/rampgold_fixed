`timescale 1ns / 1ps

`ifndef SYNP94
import libiu::*;
import libopcodes::*;
import libconf::*;
import libstd::*;
import libperfcnt::*;
import libio::*;
`else
`include "../cpu/libiu.sv"
`include "../io/libio.sv"
`include "libperfcnt.sv"
`endif


// dual ported ram, supports 2x reads and 1x write per clk cycle
module perf_cnt_ram(input iu_clk_type gclk, input rst,
input bit [NTHREADIDMSB:0] rd1_tid,
input bit [NTHREADIDMSB:0] rd2_tid,
input bit [NTHREADIDMSB:0] wr_tid,
input bit [63:0]	din,
output bit [63:0]	dout1,
output bit [63:0]	dout2,
input bit 		we);

	bit [NTHREADIDMSB:0]	raddr;
  bit [63:0] dout;

	// infer memory
	(* syn_ramstyle = "select_ram" *) bit [63:0] data[NTHREADIDMSB:0];

	//RAMs
	always_ff @(negedge gclk.clk) begin
		if (we) data[wr_tid] <= din;
	end

	assign raddr = (gclk.ce) ? rd1_tid : rd2_tid;
	assign dout = data[raddr];

	always_ff @(posedge gclk.clk2x) begin
		if (gclk.ce) dout1 <= dout;
		else dout2 <= dout;
	end
endmodule

module result_buf(input iu_clk_type gclk, input rst,
  input bit [NTHREADIDMSB:0] raddr,
  input bit [NTHREADIDMSB:0] waddr1,
  input bit [NTHREADIDMSB:0] waddr2,
  input bit we,
  input bit clear, // to clear valid bit
  input bit [31:0] din,
  output bit [31:0] dout,
  output bit dout_valid);
  
  // infer memory
  (* syn_ramstyle = "select_ram" *) bit [31:0] data[NTHREADIDMSB:0];
  (* syn_ramstyle = "select_ram" *) bit data_valid[NTHREADIDMSB:0];
  
  bit [NTHREADIDMSB:0] waddr;
  bit [31:0] vdata;
  bit vvalid;
  
  assign waddr = (gclk.ce) ? waddr2 : waddr1;
  
  always_ff @(posedge gclk.clk2x) begin
    if (~gclk.ce & we) begin
        data[waddr] = din;
        data_valid[waddr] = '1;
    end
    if (gclk.ce & clear) begin
        data_valid[waddr] = '0;
    end
  end
  
  assign vdata = data[raddr];
  assign vvalid = data_valid[raddr];
  
  always_ff @(posedge gclk.clk) begin
	dout <= vdata;
	dout_valid <= vvalid;
  end
endmodule

task automatic classify_inst(input bit [31:0] inst, output bit ldst, output bit st, output bit cti, output bit flop, output bit intop, output bit rw_state);

	bit [1:0] op;
	bit [2:0] op2;
	bit [5:0] op3;

	op = inst[31:30];
	op2 = inst[24:22];
	op3 = inst[24:19];

	ldst = '0;
	st = '0;
	cti = '0;
	flop = '0;
	intop = '0;
	rw_state = '0;

	unique case (op)
	CALL:
		cti = '1;
	FMT2: 	unique case (op2)
			SETHI:
				intop = '1;
			BICC, FBFCC, FBFCC:
				cti = '1;
			default:;
		endcase
	FMT3:	unique case (op3)
			IADD, IAND, IOR, IXOR, ISUB, ANDN, ORN, IXNOR, ADDX, UMUL, SMUL, SUBX, UDIV,
			SDIV, ADDCC, ANDCC, ORCC, XORCC, SUBCC, ANDNCC, ORNCC, XNORCC, ADDXCC, UMULCC,
			SMULCC, SUBXCC, UDIVCC, SDIVCC, TADDCC, TSUBCC, TADDCCTV, TSUBCCTV, MULSCC,
			ISLL, ISRL, ISRA:
				intop = '1;
			RDPSR, RDWIM, RDTBR, WRY, WRPSR, WRWIM, WRTBR, SAVE, RESTORE:
				rw_state = '1;
			JMPL, TICC, RETT:
				cti = '1;
			FPOP1, FPOP2:
				flop = '1;
		  default:;
		endcase
	 LDST:
	   begin
	     ldst = '1;
	     st = op3[2];
	   end
	default:;
	endcase
endtask

module perf_counters(input iu_clk_type gclk, input bit rst,
	input perf_count_write_req_in wreq_in,
	input io_bus_in_type io_in,
	output io_bus_out_type io_out);

	bit ldst, st, cti, flop, intop, rw_state;
	bit ldst_r, cti_r, flop_r, intop_r, rw_state_r;
	bit [NTHREADIDMSB:0] wtid_r, rtid_r;
	bit [IO_AWIDTH-3:0] raddr_r;

	bit [63:0] ldst_dout1, ldst_dout2, cti_dout1, cti_dout2, flop_dout1, flop_dout2;
	bit [63:0] intop_dout1, intop_dout2, rw_state_dout1, rw_state_dout2;
	bit [63:0] ldst_din, cti_din, flop_din, intop_din, rw_state_din;
	bit result_valid, result_valid0, result_valid1, result_req;
	bit result_clear0, result_clear1, vclear0, vclear1;
	bit [31:0] result_data0, result_data1;

	perf_count_read_reg rreq_r1, rreq_r2, rreq_r3, rreq_r4, rreq_r5;

	always @(posedge gclk.clk) begin
		wtid_r <= wreq_in.tid;
		ldst_r <= ldst & wreq_in.valid;
		cti_r <= cti & wreq_in.valid;
		flop_r <= flop & wreq_in.valid;
		intop_r <= intop & wreq_in.valid;
		rw_state_r <= rw_state & wreq_in.valid;

		rreq_r1.req.addr <= raddr_r;
		rreq_r1.req.tid <= rtid_r;
		rreq_r1.req.req <= result_req;
		rreq_r1.data <= (raddr_r == 0) ? ldst_dout2 : 32'b0;

		rreq_r2.req <= rreq_r1.req;
		rreq_r2.data <= (rreq_r1.req.addr == 2) ? cti_dout2 : rreq_r1.data;

		rreq_r3.req <= rreq_r2.req;
		rreq_r3.data <= (rreq_r2.req.addr == 4) ? flop_dout2 : rreq_r2.data;

		rreq_r4.req <= rreq_r3.req;
		rreq_r4.data <= (rreq_r3.req.addr == 6) ? intop_dout2 : rreq_r3.data;

		rreq_r5.req <= rreq_r4.req;
		rreq_r5.data <= (rreq_r4.req.addr == 8) ? rw_state_dout2 : rreq_r4.data;
	end

	perf_cnt_ram ldst_cnt(.gclk, .rst, .rd1_tid(wreq_in.tid), .rd2_tid(rtid_r), .wr_tid(wtid_r), .din(ldst_din), .dout1(ldst_dout1), .dout2(ldst_dout2), .we(ldst_r));

	perf_cnt_ram cti_cnt(.gclk, .rst, .rd1_tid(wreq_in.tid), .rd2_tid(rreq_r1.req.tid), .wr_tid(wtid_r), .din(cti_din), .dout1(cti_dout1), .dout2(cti_dout2), .we(cti_r));

	perf_cnt_ram flop_cnt(.gclk, .rst, .rd1_tid(wreq_in.tid), .rd2_tid(rreq_r2.req.tid), .wr_tid(wtid_r), .din(flop_din), .dout1(flop_dout1), .dout2(flop_dout2), .we(flop_r));

	perf_cnt_ram intop_cnt(.gclk, .rst, .rd1_tid(wreq_in.tid), .rd2_tid(rreq_r3.req.tid), .wr_tid(wtid_r), .din(intop_din), .dout1(intop_dout1), .dout2(intop_dout2), .we(intop_r));

	perf_cnt_ram rw_state_cnt(.gclk, .rst, .rd1_tid(wreq_in.tid), .rd2_tid(rreq_r4.req.tid), .wr_tid(wtid_r), .din(rw_state_din), .dout1(rw_state_dout1), .dout2(rw_state_dout2), .we(rw_state_r));	

	always_comb begin
		classify_inst(wreq_in.inst, ldst, st, cti, flop, intop, rw_state);
		ldst_din = ldst_dout1 + 1;
		cti_din = cti_dout1 + 1;
		flop_din = flop_dout1 + 1;
		intop_din = intop_dout1 + 1;
		rw_state_din = rw_state_dout1 + 1;
	end

	result_buf gen_result_buf0(.gclk, .rst, .raddr(io_in.tid), .waddr1(rreq_r5.req.tid), .waddr2(rtid_r), .we(rreq_r5.req.req), .clear(result_clear0), .din(rreq_r5.data[63:32]), .dout(result_data0), .dout_valid(result_valid0));

	result_buf gen_result_buf1(.gclk, .rst, .raddr(io_in.tid), .waddr1(rreq_r5.req.tid), .waddr2(rtid_r), .we(rreq_r5.req.req), .clear(result_clear1), .din(rreq_r5.data[31:0]), .dout(result_data1), .dout_valid(result_valid1));

  assign result_valid = (raddr_r[0]) ? result_valid1 : result_valid0;
  assign io_out.rdata = (raddr_r[0]) ? result_data1 : result_data0;

	always_comb begin
		io_out.retry = io_in.en & ~result_valid;
		io_out.irl = '0;

		result_clear0 = io_in.en & result_valid & ~raddr_r[0];
		result_clear1 = io_in.en & result_valid & raddr_r[0];
		result_req = io_in.en & ~result_valid;
	end

	always_ff @(posedge gclk.clk) begin
		raddr_r <= io_in.addr[IO_AWIDTH:2];
		rtid_r <= io_in.tid;
	end

endmodule


		
				
	
		

