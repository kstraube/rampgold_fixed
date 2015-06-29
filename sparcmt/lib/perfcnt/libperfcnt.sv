`timescale 1ns / 1ps

`ifndef SYNP94
package libperfcnt;
import libio::*;
import libconf::*;
`endif

typedef struct {
	bit [IO_AWIDTH-3:0] addr;
	bit [NTHREADIDMSB:0] tid;
	bit req;
} perf_count_read_req_in;

typedef struct {
	bit [63:0] data;
	bit valid;
} perf_count_read_req_out;

typedef struct {
	bit [31:0] inst;
	bit [NTHREADIDMSB:0] tid;
	bit valid;
} perf_count_write_req_in;

typedef struct {
	bit [63:0] data;
	perf_count_read_req_in req;
} perf_count_read_reg;

`ifndef SYNP94
endpackage;
`endif