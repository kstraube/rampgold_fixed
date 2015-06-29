 //synthesis translate_off

`timescale 1ns / 1ps

typedef struct {
	int		reset;
	int 		RBempty;
	int		read_data1;
	int		read_data2;
	int		read_data3;
	int		read_data4;
} read_data_type_in;

typedef struct {
	int		readRB;
} read_data_type_out;

typedef struct {
	int 		reset;
	int		AFfull;
	int		WBfull;
} write_data_type_in;

typedef struct {
	int	 	writeAF;		// write addr fifo
	int		read;			// read command
	int		addr;			// address
	int 		writeWB;		// write buffer write enable
	int 		write_data1;
	int 		write_data2;
	int 		write_data3;
	int 		write_data4;
} write_data_type_out;

import "DPI-C" context function void init_driver();
import "DPI-C" context function void do_read(input read_data_type_in rdata_in, output read_data_type_out rdata_out);
import "DPI-C" context function void do_write(input write_data_type_in wdata_in, output write_data_type_out wdata_out);

module bee3_tester(
	input 	bit clk,
	input	bit rst,

	output	bit readRB,
	input 	bit RBempty,
	input	bit [31:0] read_data1,
	input	bit [31:0] read_data2,
	input	bit [31:0] read_data3,
	input	bit [31:0] read_data4,

	output	bit writeAF,
	output	bit writeWB,
	input 	bit AFfull,
	input	bit WBfull,
	output 	bit read,
	output	bit [27:0] addr,
	output	bit [31:0] write_data1,
	output	bit [31:0] write_data2,
	output	bit [31:0] write_data3,
	output	bit [31:0] write_data4
);

initial begin
	init_driver();
end;

  read_data_type_in 	rdata_in;
  read_data_type_out 	rdata_out;
  write_data_type_in 	wdata_in;
  write_data_type_out 	wdata_out;

  always_comb begin

    readRB = '0;
    writeAF = '0;
    writeWB = '0;

 //   if (rst == 0) begin 
      readRB = int'(rdata_out.readRB);

      rdata_in.reset = int'(rst);
      rdata_in.RBempty = int'(RBempty);
      rdata_in.read_data1 = int'(read_data1);
      rdata_in.read_data2 = int'(read_data2);
      rdata_in.read_data3 = int'(read_data3);
      rdata_in.read_data4 = int'(read_data4);

      writeAF = int'(wdata_out.writeAF);
      writeWB = int'(wdata_out.writeWB);
      addr = int'(wdata_out.addr);
      read = int'(wdata_out.read);
      write_data1 = int'(wdata_out.write_data1);
      write_data2 = int'(wdata_out.write_data2);
      write_data3 = int'(wdata_out.write_data3);
      write_data4 = int'(wdata_out.write_data4);

      wdata_in.reset = int'(rst);
      wdata_in.AFfull = int'(AFfull);
      wdata_in.WBfull = int'(WBfull);

 //   end
  end

  always_ff @(negedge clk) begin
    do_write(wdata_in, wdata_out);
  end

  always_ff @(negedge clk) begin
    do_read(rdata_in, rdata_out);
  end

endmodule
      
    
    

