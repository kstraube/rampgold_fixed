`timescale 1ns / 1ps

`ifndef SYNP94
package libfedriver;
`endif

typedef struct {
  bit clk;
  bit clk2x;
} fedriver_clk_type;

typedef struct {
  bit        rst_in;
  bit [10:0] addr;
  bit        we[8];
  bit [15:0] data[8];
} fedriver_request_type;

typedef struct {
  bit [31:0] data[8];
} fedriver_response_type;

`ifndef SYNP94
endpackage
`endif