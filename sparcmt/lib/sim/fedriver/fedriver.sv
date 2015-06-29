//-------------------------------------------------------------------------------------------  
// File:        driver.sv
// Author:      Yunsup Lee
// Description: Interface between FrontEnd machine and Simulator using DPI
//-------------------------------------------------------------------------------------------   

//synthesis translate_off

`timescale 1ns / 1ps

import libfedriver::*;

typedef struct {
  int cmd; // 1: reset, 2: mem
  int rw[8];
  int unsigned addr;
  int unsigned data[8];
} request_type;

typedef struct {
  int unsigned data[8];
} response_type;

import "DPI-C" context function void init_driver();
import "DPI-C" context function void transfer(input response_type rep, output request_type req);

module fedriver(input fedriver_clk_type fe_clk, input bit fe_rst, output fedriver_request_type fe_req, input fedriver_response_type fe_rep);
  
  int i;
  request_type req;
  response_type rep;
  
  initial begin
    init_driver();
  end
  
  always_comb begin
    for (i=0;i<8;i++) begin
      rep.data[i] = '0;
    end

    fe_req.rst_in = '0;
    fe_req.addr = '0;
    for (i=0; i<8; i++) begin
      fe_req.we[i] = '0;
      fe_req.data[i] = '0;
    end
      
    if (fe_rst == 0) begin
      rep.data[0] = int'(fe_rep.data[0]);
      rep.data[1] = int'(fe_rep.data[1]);
      rep.data[2] = int'(fe_rep.data[2]);
      rep.data[3] = int'(fe_rep.data[3]);
      rep.data[4] = int'(fe_rep.data[4]);
      rep.data[5] = int'(fe_rep.data[5]);
      rep.data[6] = int'(fe_rep.data[6]);
      rep.data[7] = int'(fe_rep.data[7]);
      
      if (req.cmd == 1) begin // reset
        fe_req.rst_in = 1'b1;
      end
      else if (req.cmd == 2) begin // mem
        fe_req.rst_in = 1'b0;
        fe_req.we[0] = 1'(req.rw[0]);
        fe_req.we[1] = 1'(req.rw[1]);
        fe_req.we[2] = 1'(req.rw[2]);
        fe_req.we[3] = 1'(req.rw[3]);
        fe_req.we[4] = 1'(req.rw[4]);
        fe_req.we[5] = 1'(req.rw[5]);
        fe_req.we[6] = 1'(req.rw[6]);
        fe_req.we[7] = 1'(req.rw[7]);
        fe_req.addr = 11'(req.addr);
        fe_req.data[0] = 16'(req.data[0]);
        fe_req.data[1] = 16'(req.data[1]);
        fe_req.data[2] = 16'(req.data[2]);
        fe_req.data[3] = 16'(req.data[3]);
        fe_req.data[4] = 16'(req.data[4]);
        fe_req.data[5] = 16'(req.data[5]);
        fe_req.data[6] = 16'(req.data[6]);
        fe_req.data[7] = 16'(req.data[7]);
      end
    end
  end

  always_ff @(negedge fe_clk.clk) begin
    transfer(rep, req);
  end
  
endmodule

//synthesis translate_on
