//------------------------------------------------------------------------------ 
// File:        libperfctr.sv
// Author:      Zhangxi Tan
// Description: Data structures for performance counters
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps


`ifndef SYNP94
package libperfctr;
import libconf::*;
import libstd::*;
`endif

parameter MAX_PERFCTR = 32;
parameter PERFCTRADDRMSB = log2x(MAX_PERFCTR) - 1;

typedef struct {
   bit [NTHREADIDMSB:0]     tid;		 //thread id
   bit [PERFCTRADDRMSB:0]   addr;		//request address   
   bit                      valid; //request is valid
}perfctr_ring_ctrl_type;

typedef    bit [31:0] perfctr_ring_data_type;  //32-bit data bus (double clocked)

typedef struct {
	bit [63:0]	data;
	bit			valid;		//no parity protection
}perfctr_ring_buf_type;		//result buffer

`ifndef SYNP94
endpackage
`endif