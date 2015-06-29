//---------------------------------------------------------------------------   
// File:        top_test.sv
// Author:      Zhangxi Tan
// Description: Instantiate BEE3 mem controller for ML505/BEE3 for dual-rank 
//		2GB dimms
//------------------------------------------------------------------------------

module top_test( 
  input bit clkin_p, input bit clkin_n, input bit rstin, output bit done_led, output bit error_led,
  //rs232 signals
  input 		bit     RxD,
  output		bit     TxD,
  //SODIMM signals
  inout  [63:0]              ddr2_dq,
  output [13:0]              ddr2_a,
  output [2:0]               ddr2_ba,
  output                     ddr2_ras_n,
  output                     ddr2_cas_n,
  output                     ddr2_we_n,
  output [1:0]               ddr2_cs_n,
  output [1:0]               ddr2_odt,
  output [1:0]               ddr2_cke,
  output [7:0]               ddr2_dm,
  inout  [7:0]               ddr2_dqs,
  inout  [7:0]               ddr2_dqs_n,
  output [1:0]               ddr2_ck,
  output [1:0]               ddr2_ck_n );

wire [3:0] Leds;

ddrTop ddr2test(
 .CLKBN(clkin_n),
 .CLKBP(clkin_p),
 .FPGA_Reset(rstin),
 //Signals to the DIMMs
 .DQ(ddr2_dq),  //the 64 DQ pins
 .DQS(ddr2_dqs), //the 8  DQS pins
 .DQS_L(ddr2_dqs_n),
 .DM(ddr2_dm),
 .DIMMCK(ddr2_ck),  //differential clock to the DIMM
 .DIMMCKL(ddr2_ck_n),
 .A(ddr2_a),  //addresses to DIMMs
 .BA(ddr2_ba), //bank address to DIMMs
 .RS(ddr2_cs_n), //rank select
 .RAS(ddr2_ras_n),
 .CAS(ddr2_cas_n),
 .WE(ddr2_we_n),
 .ODT(ddr2_odt),
 .ClkEn(ddr2_cke), //common clock enable for both DIMMs. SSTL1_8
  
// input Global_Reset, //low true
// inout SCL,  //I2C clock
// inout SDA,  //I2C data
 .TxD(TxD), //RS232 transmit data
 .RxD(RxD),  //RS232 received data
 .Leds(Leds)  // 0: reading LED 1: single bit error 2: double bit errors, 3: hold fail
);

assign done_led = Leds[0];
assign error_led = Leds[3];
endmodule
