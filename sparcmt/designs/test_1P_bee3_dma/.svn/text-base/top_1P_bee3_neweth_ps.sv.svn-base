//-------------------------------------------------------------------------------------------------  
// File:        top_1P_bee3_neweth_ps.sv
// Author:      Zhangxi Tan 
// Description: Top level design for one pipeline and BEE3 dram controller (netlist simulation)
//-------------------------------------------------------------------------------------------------

`timescale 1ns / 1ps

module sim_top;

parameter clkperiod = 5;

bit clk=0, clk90;
bit clk200;
bit rst;
bit cpurst;

bit phy_rxclk, phy_gtxclk, phy_txen, phy_rxdv;
bit [7:0] phy_txd, phy_rxd;

bit	error1_led, error2_led;

//IO interface
//io_bus_out_type      io_in;
//io_bus_in_type       io_out;

wire [63:0]              ddr2_dq;
wire [13:0]              ddr2_a;
wire [2:0]               ddr2_ba;
wire                     ddr2_ras_n;
wire                     ddr2_cas_n;
wire                     ddr2_we_n;
wire [1:0]               ddr2_cs_n;
wire [1:0]               ddr2_odt;
wire [1:0]               ddr2_cke;
wire [7:0]               ddr2_dm;
wire [7:0]               ddr2_dqs;
wire [7:0]               ddr2_dqs_n;
wire [1:0]               ddr2_ck;
wire [1:0]               ddr2_ck_n;



default clocking main_clk @(posedge clk);
endclocking

initial begin
  forever #clkperiod clk = ~clk;
end

initial begin
  forever #4 phy_rxclk = ~phy_rxclk;
end

initial begin
  forever clk90 = #2500ps clk;
end

assign clk200 = clk90 ^ clk;



initial begin

  rst 	 = '0;
  cpurst = '0;
//  io_in.retry = '0;
//  io_in.irl   = '0;
//  io_in.rdata = '0;

//  ##10;
//  rst = '0;
  
  ##200;
  rst = '0;
  
  ##10;
  rst = '1;
  
  ##200;
  cpurst = '1;
  
  ##10;
  cpurst = '0;
end

mt16htf25664hy  gen_sodimm(
                         .dq(ddr2_dq),
                         .addr(ddr2_a),           //COL/ROW addr
                         .ba(ddr2_ba),            //bank addr
                         .ras_n(ddr2_ras_n),
                         .cas_n(ddr2_cas_n),
                         .we_n(ddr2_we_n),
                         .cs_n(ddr2_cs_n),
                         .odt(ddr2_odt),
                         .cke(ddr2_cke),
                         .dm(ddr2_dm),
                         .dqs(ddr2_dqs),
                         .dqs_n(ddr2_dqs_n),
                         .ck(ddr2_ck),
                         .ck_n(ddr2_ck_n)
                          );

mac_fedriver mac(
            .rxclk(phy_rxclk),
            .txclk(phy_gtxclk),
            .rst(cpurst),
            .rxdv(phy_rxdv),
            .rxd(phy_rxd),
            .txd(phy_txd),
            .txen(phy_txen));

fpga_top sim(.clkin_p(clk), 
            .clkin_n(~clk),
            .clk200_p(clk200),		//no use in simulation
            .clk200_n(~clk200),
            .rstin(rst),
            .cpurst,         
            .ddr2_dq,
            .ddr2_a,
            .ddr2_ba,
            .ddr2_ras_n,
            .ddr2_cas_n,
            .ddr2_we_n,
            .ddr2_cs_n,
            .ddr2_odt,
            .ddr2_cke,
            .ddr2_dm,
            .ddr2_dqs,
            .ddr2_dqs_n,
            .ddr2_ck,
            .ddr2_ck_n,
            .PHY_TXD(phy_txd),
            .PHY_TXEN(phy_txen),
            .PHY_TXER(),
            .PHY_GTXCLK(phy_gtxclk),
            .PHY_RXD(phy_rxd),
            .PHY_RXDV(phy_rxdv),
            .PHY_RXER(1'b0),
            .PHY_RXCLK(phy_rxclk),
            .PHY_RESET(),
            .TxD(),
            .error1_led(),
            .error2_led(),
            .RxD(1'b0)
            );



endmodule

