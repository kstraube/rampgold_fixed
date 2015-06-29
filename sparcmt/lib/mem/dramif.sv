//---------------------------------------------------------------------------   
// File:        dramif.sv
// Author:      Zhangxi Tan
// Description: Dram user interface definition
//------------------------------------------------------------------------------  
`timescale 1ns / 1ps

`ifndef DRAMUIF
`define DRAMUIF

`ifndef SYNP94
import libiu::*;
import libcache::*;
import libmemif::*;
`else
`include "../cpu/libiu.sv"
`include "../cpu/libmmu.sv"
`include "../cpu/libcache.sv"
`include "libmemif.sv"
`endif

//This is a wrapper and interface logic (e.g. extra ECC error checking on datapath and etc)
interface mem_controller_interface(input iu_clk_type gclk, input rst);
  //mem network interface
  //one-hot mux signals and registers
  imem_req_addr_buf_type   af_in;      //memory controller address fifo data input
  imem_req_data_buf_type   df_in;      //memory controller data fifo data input
  //dram user logic fifo signals (registered)
  bit                      af_full;    //address fifo is full
  bit                      wb_full;    //write buffer is full
  bit                      rb_empty;   //read buffer is empty
  bit                      rb_re;      //read buffer re
  bit                      af_we;      //write to address fifo
  bit                      wb_we;      //write to write buffer       
  bit [ICACHELINEMSB_IU+ICACHELINESIZE_IU:0]	rb_data;    //readback data
 
  //Memory controller user logic interface
  bit [27:0]  Address;
  bit         Read;        //1 = Read, 0 = Write
  bit         WriteAF;
  bit         AFfull;      //memory controller address fifo full
  bit         AFclock;
   
  bit [143:0] ReadData;    //read back data
  bit         ReadRB; 
  bit         RBempty;     //memory controller read buffer empty
  bit         RBfull;      //RB is full, used to monitor can we consume the dram data fast enough
  bit         RBclock;     //read buffer read clock
    
  bit [143:0] WriteData;
  bit         WriteWB;     //write data fifo WE
  bit         WBfull;      //memory controller write buffer full
  bit         WBclock;     //write buffer write clock
  
  bit         s_rb_re, pipe_re;
  
  bit [143:0] read_pipe[0:1];
  (* syn_maxfan=8 *) bit [1:0]   read_pipe_valid;
  bit [1:0]   read_pipe_we;
  
  bit         rb_valid;
  
  modport dram(input Address, input Read, input WriteAF, output AFfull, input AFclock, output ReadData, input ReadRB, output RBempty, output RBfull, input RBclock,
               input WriteData, input WriteWB, output WBfull, input WBclock);
  modport cpu(output af_in, output df_in, output rb_re, input af_full, input wb_full, input rb_empty, output af_we, output wb_we, input rb_data);

  //clock assignment
  assign AFclock = gclk.clk;
  assign WBclock = gclk.clk2x;    //write at clk2x               
  assign RBclock = gclk.clk2x;    //read at clk2x
  
  //wires
  assign WriteAF = af_we;
  
  assign WriteWB = wb_we;
  assign WriteData = {df_in.ecc_parity, df_in.data};
  //TODO: add IIAB's addressing scheme

  assign Address = unsigned'(af_in.addr);
  assign Read    = ~af_in.we;

//  assign rb_empty = RBempty;                    //rb_empty -> mem network is a multicycle path

//  assign ReadRB = (gclk.ce) ? s_rb_re  : rb_re ;
  always_ff @(negedge gclk.clk) s_rb_re <= rb_re;
  
  //dram user logic FIFO 
  always_ff @(posedge gclk.clk) begin
    af_full  <= AFfull;
    wb_full  <= WBfull;    
  end
  

//  always_ff @(posedge gclk.clk2x) 
//    rb_data <= ReadData;

  always_comb begin        
    rb_valid = ~RBempty;
    
    pipe_re = (gclk.ce) ? s_rb_re : rb_re;
    
    read_pipe_we[1] = pipe_re | ~read_pipe_valid[1];
    read_pipe_we[0] = read_pipe_we[1] | ~read_pipe_valid[0];
    
    ReadRB = read_pipe_we[0] & rb_valid;
    
    rb_empty = ~read_pipe_valid[0] | ~read_pipe_valid[1];
  end
  
  always_ff @(posedge gclk.clk2x) begin
    if  (rst) 
      read_pipe_valid <= '0;
    else begin 
     if (read_pipe_we[0]) read_pipe_valid[0] <= rb_valid;      
     if (read_pipe_we[1]) read_pipe_valid[1] <= read_pipe_valid[0];
    end

    if (read_pipe_we[0]) read_pipe[0] <= ReadData;
    if (read_pipe_we[1]) read_pipe[1] <= read_pipe[0];
    
    rb_data <= read_pipe[1];
  end
    
endinterface

`endif