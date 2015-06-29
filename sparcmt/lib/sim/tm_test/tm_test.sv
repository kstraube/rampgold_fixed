import libiu::*;
import libio::*;
import libtm::*;
import libconf::*;

`timescale 1ns / 1ps

module sim_top;

string path = "/scratch/waterman/Software/build/";
//string cmdline = {"-f",path,"bin/appserver.conf fs ",path,"../Verification/MMU/trivial none"};
string cmdline = {"-f",path,"bin/appserver.conf fs ",path,"rampbin/kernel.stats ",path,"rampbin/nop"};
//string cmdline = {"-f",path,"bin/appserver.conf fs ",path,"rampbin/kernel.stats /scratch/xtan/OCEAN_nodiv -p4 -n6 -o"};
//string cmdline = {"-f",path,"bin/appserver.conf fs ",path,"rampbin/kernel.stats ",path,"rampbin/memlatency"};
int ncores = 64;
int silent = 0;
parameter PIPELINE_DEPTH = 8;

parameter clkperiod = 5;
iu_clk_type gclk;
default clocking main_clk @(posedge gclk.clk2x);
endclocking
initial begin
  gclk.clk = 0;
  gclk.clk2x = 0;
  forever #clkperiod gclk.clk2x = ~gclk.clk2x;
end
always @(posedge gclk.clk2x)
  gclk.clk <= ~gclk.clk;
assign #1 gclk.ce = ~gclk.clk;

bit rst,tick;
dma_tm_ctrl_type dma2tm;
initial begin
  rst = 1;
  dma2tm.threads_total = NTHREAD-1;
  dma2tm.threads_active = ncores-1;
  dma2tm.tm_dbg_ctrl = tm_dbg_nop;
  
  ##2000;
  rst = 0;

  ##40;
  dma2tm.tm_dbg_ctrl = tm_dbg_start;

  ##20;
  dma2tm.tm_dbg_ctrl = tm_dbg_nop;
end

import "DPI-C" task tick_simulator(input tm2cpu_token_type tm2cpu, output tm_cpu_ctrl_token_type cpu2tm, input io_bus_out_type io_tm2cpu, output io_bus_in_type io_cpu2tm);
import "DPI-C" task init_simulator(input string cmdline, input int ncores, input int silent);

tm2cpu_token_type tm2cpu;
tm_cpu_ctrl_token_type cpu2tm_pipe[PIPELINE_DEPTH];
io_bus_in_type io_cpu2tm;
io_bus_out_type io_tm2cpu;
bit running;

always @(posedge gclk.clk) begin
  cpu2tm_pipe[1:PIPELINE_DEPTH-1] <= cpu2tm_pipe[0:PIPELINE_DEPTH-2];
  tick_simulator(tm2cpu,cpu2tm_pipe[0],io_tm2cpu,io_cpu2tm);
end

initial begin
  init_simulator(cmdline,ncores,silent);
end

tm_cpu_l1 gen_tm(.*,.cpu2tm(cpu2tm_pipe[PIPELINE_DEPTH-1]),.io_in(io_cpu2tm),.io_out(io_tm2cpu));

endmodule
