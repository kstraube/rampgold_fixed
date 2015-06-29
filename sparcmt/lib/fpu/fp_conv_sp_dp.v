////////////////////////////////////////////////////////////////////////////////
// Copyright (c) 1995-2009 Xilinx, Inc.  All rights reserved.
////////////////////////////////////////////////////////////////////////////////
//   ____  ____
//  /   /\/   /
// /___/  \  /    Vendor: Xilinx
// \   \   \/     Version: L.46
//  \   \         Application: netgen
//  /   /         Filename: fp_conv_sp_dp.v
// /___/   /\     Timestamp: Tue Jun 30 12:51:25 2009
// \   \  /  \ 
//  \___\/\___\
//             
// Command	: -intstyle ise -w -sim -ofmt verilog ./tmp/_cg/fp_conv_sp_dp.ngc ./tmp/_cg/fp_conv_sp_dp.v 
// Device	: 5vlx110tff1136-1
// Input file	: ./tmp/_cg/fp_conv_sp_dp.ngc
// Output file	: ./tmp/_cg/fp_conv_sp_dp.v
// # of Modules	: 1
// Design Name	: fp_conv_sp_dp
// Xilinx        : /opt/Xilinx/11.1/ISE
//             
// Purpose:    
//     This verilog netlist is a verification model and uses simulation 
//     primitives which may not represent the true implementation of the 
//     device, however the netlist is functionally correct and should not 
//     be modified. This file cannot be synthesized and should only be used 
//     with supported simulation tools.
//             
// Reference:  
//     Command Line Tools User Guide, Chapter 23 and Synthesis and Simulation Design Guide, Chapter 6
//             
////////////////////////////////////////////////////////////////////////////////

`timescale 1 ns/1 ps

module fp_conv_sp_dp (
  sclr, rdy, operation_nd, clk, a, result
)/* synthesis syn_black_box syn_noprune=1 */;
  input sclr;
  output rdy;
  input operation_nd;
  input clk;
  input [31 : 0] a;
  output [63 : 0] result;
  
  // synthesis translate_off
  
  wire \blk00000003/sig000000a9 ;
  wire \blk00000003/sig000000a8 ;
  wire \blk00000003/sig000000a7 ;
  wire \blk00000003/sig000000a6 ;
  wire \blk00000003/sig000000a5 ;
  wire \blk00000003/sig000000a4 ;
  wire \blk00000003/sig000000a3 ;
  wire \blk00000003/sig000000a2 ;
  wire \blk00000003/sig000000a1 ;
  wire \blk00000003/sig000000a0 ;
  wire \blk00000003/sig0000009f ;
  wire \blk00000003/sig0000009e ;
  wire \blk00000003/sig0000009d ;
  wire \blk00000003/sig0000009c ;
  wire \blk00000003/sig0000009b ;
  wire \blk00000003/sig0000009a ;
  wire \blk00000003/sig00000099 ;
  wire \blk00000003/sig00000098 ;
  wire \blk00000003/sig00000097 ;
  wire \blk00000003/sig00000096 ;
  wire \blk00000003/sig00000095 ;
  wire \blk00000003/sig00000094 ;
  wire \blk00000003/sig00000093 ;
  wire \blk00000003/sig00000092 ;
  wire \blk00000003/sig00000091 ;
  wire \blk00000003/sig00000090 ;
  wire \blk00000003/sig0000008f ;
  wire \blk00000003/sig0000008e ;
  wire \blk00000003/sig0000008d ;
  wire \blk00000003/sig0000008c ;
  wire \blk00000003/sig0000008b ;
  wire \blk00000003/sig0000008a ;
  wire \blk00000003/sig00000089 ;
  wire \blk00000003/sig00000088 ;
  wire \blk00000003/sig00000087 ;
  wire \blk00000003/sig00000086 ;
  wire \blk00000003/sig00000085 ;
  wire \blk00000003/sig00000084 ;
  wire \blk00000003/sig00000083 ;
  wire \blk00000003/sig00000082 ;
  wire \blk00000003/sig00000081 ;
  wire \blk00000003/sig00000080 ;
  wire \blk00000003/sig0000007f ;
  wire \blk00000003/sig0000007e ;
  wire \blk00000003/sig0000007d ;
  wire \blk00000003/sig0000007c ;
  wire \blk00000003/sig0000007b ;
  wire \blk00000003/sig0000007a ;
  wire \blk00000003/sig00000079 ;
  wire \blk00000003/sig00000078 ;
  wire \blk00000003/sig00000077 ;
  wire \blk00000003/sig00000076 ;
  wire \blk00000003/sig00000075 ;
  wire \blk00000003/sig00000074 ;
  wire \blk00000003/sig00000073 ;
  wire \blk00000003/sig00000072 ;
  wire \blk00000003/sig00000071 ;
  wire \blk00000003/sig00000070 ;
  wire \blk00000003/sig0000006f ;
  wire \blk00000003/sig0000006e ;
  wire \blk00000003/sig0000006d ;
  wire \blk00000003/sig0000006c ;
  wire \blk00000003/sig0000006b ;
  wire \blk00000003/sig0000006a ;
  wire \blk00000003/sig00000069 ;
  wire \blk00000003/sig00000068 ;
  wire \blk00000003/sig00000067 ;
  wire \blk00000003/sig00000066 ;
  wire \blk00000003/sig00000065 ;
  wire \blk00000003/sig00000064 ;
  wire \blk00000003/sig00000063 ;
  wire \blk00000003/sig00000062 ;
  wire \blk00000003/sig00000061 ;
  wire \blk00000003/sig00000060 ;
  wire \blk00000003/sig0000005f ;
  wire \blk00000003/sig0000005e ;
  wire \blk00000003/sig0000005d ;
  wire \blk00000003/sig0000005c ;
  wire \blk00000003/sig0000005b ;
  wire \blk00000003/sig0000005a ;
  wire \blk00000003/sig00000059 ;
  wire \blk00000003/sig00000058 ;
  wire \blk00000003/sig00000057 ;
  wire \blk00000003/sig00000056 ;
  wire \blk00000003/sig00000055 ;
  wire \blk00000003/sig00000054 ;
  wire \blk00000003/sig00000053 ;
  wire \blk00000003/sig00000052 ;
  wire \blk00000003/sig00000051 ;
  wire \blk00000003/sig00000050 ;
  wire \blk00000003/sig0000004f ;
  wire \blk00000003/sig0000004e ;
  wire \blk00000003/sig0000004d ;
  wire \blk00000003/sig0000004c ;
  wire \blk00000003/sig0000004b ;
  wire \blk00000003/sig0000004a ;
  wire \blk00000003/sig00000049 ;
  wire \blk00000003/sig00000048 ;
  wire \blk00000003/sig00000003 ;
  wire NLW_blk00000001_P_UNCONNECTED;
  wire NLW_blk00000002_G_UNCONNECTED;
  wire [31 : 0] a_0;
  wire [59 : 59] NlwRenamedSignal_result;
  wire [0 : 0] NlwRenamedSig_OI_result;
  assign
    a_0[31] = a[31],
    a_0[30] = a[30],
    a_0[29] = a[29],
    a_0[28] = a[28],
    a_0[27] = a[27],
    a_0[26] = a[26],
    a_0[25] = a[25],
    a_0[24] = a[24],
    a_0[23] = a[23],
    a_0[22] = a[22],
    a_0[21] = a[21],
    a_0[20] = a[20],
    a_0[19] = a[19],
    a_0[18] = a[18],
    a_0[17] = a[17],
    a_0[16] = a[16],
    a_0[15] = a[15],
    a_0[14] = a[14],
    a_0[13] = a[13],
    a_0[12] = a[12],
    a_0[11] = a[11],
    a_0[10] = a[10],
    a_0[9] = a[9],
    a_0[8] = a[8],
    a_0[7] = a[7],
    a_0[6] = a[6],
    a_0[5] = a[5],
    a_0[4] = a[4],
    a_0[3] = a[3],
    a_0[2] = a[2],
    a_0[1] = a[1],
    a_0[0] = a[0],
    result[61] = NlwRenamedSignal_result[59],
    result[60] = NlwRenamedSignal_result[59],
    result[59] = NlwRenamedSignal_result[59],
    result[28] = NlwRenamedSig_OI_result[0],
    result[27] = NlwRenamedSig_OI_result[0],
    result[26] = NlwRenamedSig_OI_result[0],
    result[25] = NlwRenamedSig_OI_result[0],
    result[24] = NlwRenamedSig_OI_result[0],
    result[23] = NlwRenamedSig_OI_result[0],
    result[22] = NlwRenamedSig_OI_result[0],
    result[21] = NlwRenamedSig_OI_result[0],
    result[20] = NlwRenamedSig_OI_result[0],
    result[19] = NlwRenamedSig_OI_result[0],
    result[18] = NlwRenamedSig_OI_result[0],
    result[17] = NlwRenamedSig_OI_result[0],
    result[16] = NlwRenamedSig_OI_result[0],
    result[15] = NlwRenamedSig_OI_result[0],
    result[14] = NlwRenamedSig_OI_result[0],
    result[13] = NlwRenamedSig_OI_result[0],
    result[12] = NlwRenamedSig_OI_result[0],
    result[11] = NlwRenamedSig_OI_result[0],
    result[10] = NlwRenamedSig_OI_result[0],
    result[9] = NlwRenamedSig_OI_result[0],
    result[8] = NlwRenamedSig_OI_result[0],
    result[7] = NlwRenamedSig_OI_result[0],
    result[6] = NlwRenamedSig_OI_result[0],
    result[5] = NlwRenamedSig_OI_result[0],
    result[4] = NlwRenamedSig_OI_result[0],
    result[3] = NlwRenamedSig_OI_result[0],
    result[2] = NlwRenamedSig_OI_result[0],
    result[1] = NlwRenamedSig_OI_result[0],
    result[0] = NlwRenamedSig_OI_result[0];
  VCC   blk00000001 (
    .P(NLW_blk00000001_P_UNCONNECTED)
  );
  GND   blk00000002 (
    .G(NLW_blk00000002_G_UNCONNECTED)
  );
  LUT3 #(
    .INIT ( 8'hC6 ))
  \blk00000003/blk00000089  (
    .I0(\blk00000003/sig00000084 ),
    .I1(\blk00000003/sig000000a8 ),
    .I2(\blk00000003/sig000000a6 ),
    .O(\blk00000003/sig000000a7 )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk00000088  (
    .I0(\blk00000003/sig00000084 ),
    .I1(\blk00000003/sig000000a8 ),
    .I2(\blk00000003/sig000000a6 ),
    .O(\blk00000003/sig000000a5 )
  );
  LUT2 #(
    .INIT ( 4'h2 ))
  \blk00000003/blk00000087  (
    .I0(\blk00000003/sig00000084 ),
    .I1(\blk00000003/sig000000a6 ),
    .O(\blk00000003/sig000000a9 )
  );
  FDS #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000086  (
    .C(clk),
    .D(\blk00000003/sig000000a9 ),
    .S(sclr),
    .Q(\blk00000003/sig00000084 )
  );
  FDS #(
    .INIT ( 1'b1 ))
  \blk00000003/blk00000085  (
    .C(clk),
    .D(\blk00000003/sig000000a7 ),
    .S(sclr),
    .Q(\blk00000003/sig000000a8 )
  );
  FDS #(
    .INIT ( 1'b1 ))
  \blk00000003/blk00000084  (
    .C(clk),
    .D(\blk00000003/sig000000a5 ),
    .S(sclr),
    .Q(\blk00000003/sig000000a6 )
  );
  LUT4 #(
    .INIT ( 16'h330A ))
  \blk00000003/blk00000083  (
    .I0(\blk00000003/sig0000004c ),
    .I1(\blk00000003/sig00000078 ),
    .I2(\blk00000003/sig00000081 ),
    .I3(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig000000a4 )
  );
  FD   \blk00000003/blk00000082  (
    .C(clk),
    .D(\blk00000003/sig000000a4 ),
    .Q(result[51])
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk00000081  (
    .I0(\blk00000003/sig00000064 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig000000a2 )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk00000080  (
    .I0(\blk00000003/sig00000065 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig000000a1 )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007f  (
    .I0(\blk00000003/sig00000066 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig000000a0 )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007e  (
    .I0(\blk00000003/sig00000067 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009f )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007d  (
    .I0(\blk00000003/sig00000068 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009e )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007c  (
    .I0(\blk00000003/sig00000069 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009d )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007b  (
    .I0(\blk00000003/sig0000006a ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009c )
  );
  LUT3 #(
    .INIT ( 8'hF2 ))
  \blk00000003/blk0000007a  (
    .I0(\blk00000003/sig0000006b ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009b )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000079  (
    .I0(\blk00000003/sig00000060 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000009a )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000078  (
    .I0(\blk00000003/sig00000061 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000099 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000077  (
    .I0(\blk00000003/sig0000005f ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000098 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000076  (
    .I0(\blk00000003/sig0000005e ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000097 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000075  (
    .I0(\blk00000003/sig0000005d ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000096 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000074  (
    .I0(\blk00000003/sig00000062 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000095 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000073  (
    .I0(\blk00000003/sig00000057 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000094 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000072  (
    .I0(\blk00000003/sig0000005c ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000093 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000071  (
    .I0(\blk00000003/sig00000056 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000092 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000070  (
    .I0(\blk00000003/sig0000005b ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000091 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006f  (
    .I0(\blk00000003/sig00000055 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000090 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006e  (
    .I0(\blk00000003/sig00000054 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008f )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006d  (
    .I0(\blk00000003/sig0000005a ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008e )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006c  (
    .I0(\blk00000003/sig00000059 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008d )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006b  (
    .I0(\blk00000003/sig00000053 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008c )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk0000006a  (
    .I0(\blk00000003/sig00000058 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008b )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000069  (
    .I0(\blk00000003/sig00000052 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig0000008a )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000068  (
    .I0(\blk00000003/sig0000004d ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000089 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000067  (
    .I0(\blk00000003/sig00000051 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000088 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000066  (
    .I0(\blk00000003/sig0000004e ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000087 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000065  (
    .I0(\blk00000003/sig00000050 ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000086 )
  );
  LUT3 #(
    .INIT ( 8'h02 ))
  \blk00000003/blk00000064  (
    .I0(\blk00000003/sig0000004f ),
    .I1(\blk00000003/sig00000081 ),
    .I2(\blk00000003/sig00000082 ),
    .O(\blk00000003/sig00000085 )
  );
  LUT3 #(
    .INIT ( 8'hCD ))
  \blk00000003/blk00000063  (
    .I0(\blk00000003/sig0000006b ),
    .I1(\blk00000003/sig00000082 ),
    .I2(\blk00000003/sig00000081 ),
    .O(\blk00000003/sig000000a3 )
  );
  FD   \blk00000003/blk00000062  (
    .C(clk),
    .D(\blk00000003/sig000000a3 ),
    .Q(NlwRenamedSignal_result[59])
  );
  FD   \blk00000003/blk00000061  (
    .C(clk),
    .D(\blk00000003/sig000000a2 ),
    .Q(result[52])
  );
  FD   \blk00000003/blk00000060  (
    .C(clk),
    .D(\blk00000003/sig000000a1 ),
    .Q(result[53])
  );
  FD   \blk00000003/blk0000005f  (
    .C(clk),
    .D(\blk00000003/sig000000a0 ),
    .Q(result[54])
  );
  FD   \blk00000003/blk0000005e  (
    .C(clk),
    .D(\blk00000003/sig0000009f ),
    .Q(result[55])
  );
  FD   \blk00000003/blk0000005d  (
    .C(clk),
    .D(\blk00000003/sig0000009e ),
    .Q(result[56])
  );
  FD   \blk00000003/blk0000005c  (
    .C(clk),
    .D(\blk00000003/sig0000009d ),
    .Q(result[57])
  );
  FD   \blk00000003/blk0000005b  (
    .C(clk),
    .D(\blk00000003/sig0000009c ),
    .Q(result[58])
  );
  FD   \blk00000003/blk0000005a  (
    .C(clk),
    .D(\blk00000003/sig0000009b ),
    .Q(result[62])
  );
  FD   \blk00000003/blk00000059  (
    .C(clk),
    .D(\blk00000003/sig0000009a ),
    .Q(result[31])
  );
  FD   \blk00000003/blk00000058  (
    .C(clk),
    .D(\blk00000003/sig00000099 ),
    .Q(result[30])
  );
  FD   \blk00000003/blk00000057  (
    .C(clk),
    .D(\blk00000003/sig00000098 ),
    .Q(result[32])
  );
  FD   \blk00000003/blk00000056  (
    .C(clk),
    .D(\blk00000003/sig00000097 ),
    .Q(result[33])
  );
  FD   \blk00000003/blk00000055  (
    .C(clk),
    .D(\blk00000003/sig00000096 ),
    .Q(result[34])
  );
  FD   \blk00000003/blk00000054  (
    .C(clk),
    .D(\blk00000003/sig00000095 ),
    .Q(result[29])
  );
  FD   \blk00000003/blk00000053  (
    .C(clk),
    .D(\blk00000003/sig00000094 ),
    .Q(result[40])
  );
  FD   \blk00000003/blk00000052  (
    .C(clk),
    .D(\blk00000003/sig00000093 ),
    .Q(result[35])
  );
  FD   \blk00000003/blk00000051  (
    .C(clk),
    .D(\blk00000003/sig00000092 ),
    .Q(result[41])
  );
  FD   \blk00000003/blk00000050  (
    .C(clk),
    .D(\blk00000003/sig00000091 ),
    .Q(result[36])
  );
  FD   \blk00000003/blk0000004f  (
    .C(clk),
    .D(\blk00000003/sig00000090 ),
    .Q(result[42])
  );
  FD   \blk00000003/blk0000004e  (
    .C(clk),
    .D(\blk00000003/sig0000008f ),
    .Q(result[43])
  );
  FD   \blk00000003/blk0000004d  (
    .C(clk),
    .D(\blk00000003/sig0000008e ),
    .Q(result[37])
  );
  FD   \blk00000003/blk0000004c  (
    .C(clk),
    .D(\blk00000003/sig0000008d ),
    .Q(result[38])
  );
  FD   \blk00000003/blk0000004b  (
    .C(clk),
    .D(\blk00000003/sig0000008c ),
    .Q(result[44])
  );
  FD   \blk00000003/blk0000004a  (
    .C(clk),
    .D(\blk00000003/sig0000008b ),
    .Q(result[39])
  );
  FD   \blk00000003/blk00000049  (
    .C(clk),
    .D(\blk00000003/sig0000008a ),
    .Q(result[45])
  );
  FD   \blk00000003/blk00000048  (
    .C(clk),
    .D(\blk00000003/sig00000089 ),
    .Q(result[50])
  );
  FD   \blk00000003/blk00000047  (
    .C(clk),
    .D(\blk00000003/sig00000088 ),
    .Q(result[46])
  );
  FD   \blk00000003/blk00000046  (
    .C(clk),
    .D(\blk00000003/sig00000087 ),
    .Q(result[49])
  );
  FD   \blk00000003/blk00000045  (
    .C(clk),
    .D(\blk00000003/sig00000086 ),
    .Q(result[47])
  );
  FD   \blk00000003/blk00000044  (
    .C(clk),
    .D(\blk00000003/sig00000085 ),
    .Q(result[48])
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk00000043  (
    .I0(a_0[0]),
    .I1(a_0[1]),
    .I2(a_0[2]),
    .I3(a_0[3]),
    .O(\blk00000003/sig00000077 )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk00000042  (
    .I0(a_0[4]),
    .I1(a_0[5]),
    .I2(a_0[6]),
    .I3(a_0[7]),
    .O(\blk00000003/sig00000076 )
  );
  LUT3 #(
    .INIT ( 8'hA2 ))
  \blk00000003/blk00000041  (
    .I0(\blk00000003/sig00000083 ),
    .I1(\blk00000003/sig00000082 ),
    .I2(\blk00000003/sig00000078 ),
    .O(\blk00000003/sig00000063 )
  );
  LUT2 #(
    .INIT ( 4'h2 ))
  \blk00000003/blk00000040  (
    .I0(\blk00000003/sig0000004b ),
    .I1(\blk00000003/sig00000084 ),
    .O(\blk00000003/sig00000048 )
  );
  LUT2 #(
    .INIT ( 4'h8 ))
  \blk00000003/blk0000003f  (
    .I0(operation_nd),
    .I1(\blk00000003/sig00000049 ),
    .O(\blk00000003/sig0000004a )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk0000003e  (
    .I0(a_0[8]),
    .I1(a_0[9]),
    .I2(a_0[10]),
    .I3(a_0[11]),
    .O(\blk00000003/sig00000074 )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk0000003d  (
    .I0(a_0[12]),
    .I1(a_0[13]),
    .I2(a_0[14]),
    .I3(a_0[15]),
    .O(\blk00000003/sig00000072 )
  );
  LUT4 #(
    .INIT ( 16'h8000 ))
  \blk00000003/blk0000003c  (
    .I0(a_0[23]),
    .I1(a_0[24]),
    .I2(a_0[25]),
    .I3(a_0[26]),
    .O(\blk00000003/sig0000007d )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk0000003b  (
    .I0(a_0[23]),
    .I1(a_0[24]),
    .I2(a_0[25]),
    .I3(a_0[26]),
    .O(\blk00000003/sig00000079 )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk0000003a  (
    .I0(a_0[16]),
    .I1(a_0[17]),
    .I2(a_0[18]),
    .I3(a_0[19]),
    .O(\blk00000003/sig00000070 )
  );
  LUT4 #(
    .INIT ( 16'h8000 ))
  \blk00000003/blk00000039  (
    .I0(a_0[27]),
    .I1(a_0[28]),
    .I2(a_0[29]),
    .I3(a_0[30]),
    .O(\blk00000003/sig0000007f )
  );
  LUT4 #(
    .INIT ( 16'h0001 ))
  \blk00000003/blk00000038  (
    .I0(a_0[27]),
    .I1(a_0[28]),
    .I2(a_0[29]),
    .I3(a_0[30]),
    .O(\blk00000003/sig0000007b )
  );
  LUT3 #(
    .INIT ( 8'h01 ))
  \blk00000003/blk00000037  (
    .I0(a_0[20]),
    .I1(a_0[21]),
    .I2(a_0[22]),
    .O(\blk00000003/sig0000006d )
  );
  FDE #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000036  (
    .C(clk),
    .CE(\blk00000003/sig00000003 ),
    .D(a_0[31]),
    .Q(\blk00000003/sig00000083 )
  );
  FDE #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000035  (
    .C(clk),
    .CE(\blk00000003/sig00000003 ),
    .D(\blk00000003/sig00000080 ),
    .Q(\blk00000003/sig00000082 )
  );
  FDE #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000034  (
    .C(clk),
    .CE(\blk00000003/sig00000003 ),
    .D(\blk00000003/sig0000007c ),
    .Q(\blk00000003/sig00000081 )
  );
  MUXCY   \blk00000003/blk00000033  (
    .CI(\blk00000003/sig0000007e ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig0000007f ),
    .O(\blk00000003/sig00000080 )
  );
  MUXCY   \blk00000003/blk00000032  (
    .CI(\blk00000003/sig00000003 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig0000007d ),
    .O(\blk00000003/sig0000007e )
  );
  MUXCY   \blk00000003/blk00000031  (
    .CI(\blk00000003/sig0000007a ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig0000007b ),
    .O(\blk00000003/sig0000007c )
  );
  MUXCY   \blk00000003/blk00000030  (
    .CI(\blk00000003/sig00000003 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000079 ),
    .O(\blk00000003/sig0000007a )
  );
  FDE #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000002f  (
    .C(clk),
    .CE(\blk00000003/sig00000003 ),
    .D(\blk00000003/sig0000006e ),
    .Q(\blk00000003/sig00000078 )
  );
  MUXCY   \blk00000003/blk0000002e  (
    .CI(\blk00000003/sig00000003 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000077 ),
    .O(\blk00000003/sig00000075 )
  );
  MUXCY   \blk00000003/blk0000002d  (
    .CI(\blk00000003/sig00000075 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000076 ),
    .O(\blk00000003/sig00000073 )
  );
  MUXCY   \blk00000003/blk0000002c  (
    .CI(\blk00000003/sig00000073 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000074 ),
    .O(\blk00000003/sig00000071 )
  );
  MUXCY   \blk00000003/blk0000002b  (
    .CI(\blk00000003/sig00000071 ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000072 ),
    .O(\blk00000003/sig0000006f )
  );
  MUXCY   \blk00000003/blk0000002a  (
    .CI(\blk00000003/sig0000006f ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig00000070 ),
    .O(\blk00000003/sig0000006c )
  );
  MUXCY   \blk00000003/blk00000029  (
    .CI(\blk00000003/sig0000006c ),
    .DI(NlwRenamedSig_OI_result[0]),
    .S(\blk00000003/sig0000006d ),
    .O(\blk00000003/sig0000006e )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000028  (
    .C(clk),
    .D(a_0[30]),
    .Q(\blk00000003/sig0000006b )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000027  (
    .C(clk),
    .D(a_0[29]),
    .Q(\blk00000003/sig0000006a )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000026  (
    .C(clk),
    .D(a_0[28]),
    .Q(\blk00000003/sig00000069 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000025  (
    .C(clk),
    .D(a_0[27]),
    .Q(\blk00000003/sig00000068 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000024  (
    .C(clk),
    .D(a_0[26]),
    .Q(\blk00000003/sig00000067 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000023  (
    .C(clk),
    .D(a_0[25]),
    .Q(\blk00000003/sig00000066 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000022  (
    .C(clk),
    .D(a_0[24]),
    .Q(\blk00000003/sig00000065 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000021  (
    .C(clk),
    .D(a_0[23]),
    .Q(\blk00000003/sig00000064 )
  );
  FDRS   \blk00000003/blk00000020  (
    .C(clk),
    .D(\blk00000003/sig00000063 ),
    .R(NlwRenamedSig_OI_result[0]),
    .S(NlwRenamedSig_OI_result[0]),
    .Q(result[63])
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001f  (
    .C(clk),
    .D(a_0[0]),
    .Q(\blk00000003/sig00000062 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001e  (
    .C(clk),
    .D(a_0[1]),
    .Q(\blk00000003/sig00000061 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001d  (
    .C(clk),
    .D(a_0[2]),
    .Q(\blk00000003/sig00000060 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001c  (
    .C(clk),
    .D(a_0[3]),
    .Q(\blk00000003/sig0000005f )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001b  (
    .C(clk),
    .D(a_0[4]),
    .Q(\blk00000003/sig0000005e )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000001a  (
    .C(clk),
    .D(a_0[5]),
    .Q(\blk00000003/sig0000005d )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000019  (
    .C(clk),
    .D(a_0[6]),
    .Q(\blk00000003/sig0000005c )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000018  (
    .C(clk),
    .D(a_0[7]),
    .Q(\blk00000003/sig0000005b )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000017  (
    .C(clk),
    .D(a_0[8]),
    .Q(\blk00000003/sig0000005a )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000016  (
    .C(clk),
    .D(a_0[9]),
    .Q(\blk00000003/sig00000059 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000015  (
    .C(clk),
    .D(a_0[10]),
    .Q(\blk00000003/sig00000058 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000014  (
    .C(clk),
    .D(a_0[11]),
    .Q(\blk00000003/sig00000057 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000013  (
    .C(clk),
    .D(a_0[12]),
    .Q(\blk00000003/sig00000056 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000012  (
    .C(clk),
    .D(a_0[13]),
    .Q(\blk00000003/sig00000055 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000011  (
    .C(clk),
    .D(a_0[14]),
    .Q(\blk00000003/sig00000054 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000010  (
    .C(clk),
    .D(a_0[15]),
    .Q(\blk00000003/sig00000053 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000f  (
    .C(clk),
    .D(a_0[16]),
    .Q(\blk00000003/sig00000052 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000e  (
    .C(clk),
    .D(a_0[17]),
    .Q(\blk00000003/sig00000051 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000d  (
    .C(clk),
    .D(a_0[18]),
    .Q(\blk00000003/sig00000050 )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000c  (
    .C(clk),
    .D(a_0[19]),
    .Q(\blk00000003/sig0000004f )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000b  (
    .C(clk),
    .D(a_0[20]),
    .Q(\blk00000003/sig0000004e )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk0000000a  (
    .C(clk),
    .D(a_0[21]),
    .Q(\blk00000003/sig0000004d )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000009  (
    .C(clk),
    .D(a_0[22]),
    .Q(\blk00000003/sig0000004c )
  );
  FD #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000008  (
    .C(clk),
    .D(\blk00000003/sig0000004a ),
    .Q(\blk00000003/sig0000004b )
  );
  FDR #(
    .INIT ( 1'b1 ))
  \blk00000003/blk00000007  (
    .C(clk),
    .D(\blk00000003/sig00000003 ),
    .R(sclr),
    .Q(\blk00000003/sig00000049 )
  );
  FDR #(
    .INIT ( 1'b0 ))
  \blk00000003/blk00000006  (
    .C(clk),
    .D(\blk00000003/sig00000048 ),
    .R(sclr),
    .Q(rdy)
  );
  VCC   \blk00000003/blk00000005  (
    .P(\blk00000003/sig00000003 )
  );
  GND   \blk00000003/blk00000004  (
    .G(NlwRenamedSig_OI_result[0])
  );

// synthesis translate_on

endmodule

// synthesis translate_off

`ifndef GLBL
`define GLBL

`timescale  1 ps / 1 ps

module glbl ();

    parameter ROC_WIDTH = 100000;
    parameter TOC_WIDTH = 0;

    wire GSR;
    wire GTS;
    wire PRLD;

    reg GSR_int;
    reg GTS_int;
    reg PRLD_int;

//--------   JTAG Globals --------------
    wire JTAG_TDO_GLBL;
    wire JTAG_TCK_GLBL;
    wire JTAG_TDI_GLBL;
    wire JTAG_TMS_GLBL;
    wire JTAG_TRST_GLBL;

    reg JTAG_CAPTURE_GLBL;
    reg JTAG_RESET_GLBL;
    reg JTAG_SHIFT_GLBL;
    reg JTAG_UPDATE_GLBL;
    reg JTAG_RUNTEST_GLBL;

    reg JTAG_SEL1_GLBL = 0;
    reg JTAG_SEL2_GLBL = 0 ;
    reg JTAG_SEL3_GLBL = 0;
    reg JTAG_SEL4_GLBL = 0;

    reg JTAG_USER_TDO1_GLBL = 1'bz;
    reg JTAG_USER_TDO2_GLBL = 1'bz;
    reg JTAG_USER_TDO3_GLBL = 1'bz;
    reg JTAG_USER_TDO4_GLBL = 1'bz;

    assign (weak1, weak0) GSR = GSR_int;
    assign (weak1, weak0) GTS = GTS_int;
    assign (weak1, weak0) PRLD = PRLD_int;

    initial begin
	GSR_int = 1'b1;
	PRLD_int = 1'b1;
	#(ROC_WIDTH)
	GSR_int = 1'b0;
	PRLD_int = 1'b0;
    end

    initial begin
	GTS_int = 1'b1;
	#(TOC_WIDTH)
	GTS_int = 1'b0;
    end

endmodule

`endif

// synthesis translate_on
