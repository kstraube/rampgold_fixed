//-------------------------------------------------------------------------------------------------  
// File:        mac_gmii.sv
// Author:      Zhangxi Tan 
// Description: Virtex 5 Gigabit MAC, clocking scheme from Microsoft BEEhive
//-------------------------------------------------------------------------------------------------

`timescale 1ns / 1ps

`ifndef SYNP94
import libeth::*;
`else
`include "../../../eth/libeth.sv"
`endif


module xcv5_mac_gmii #(parameter CLKMUL = 5, parameter CLKDIV = 4,  parameter CLKIN_PERIOD = 10.0, parameter BOARDSEL=1) 
(    
    //clock
    input bit           reset /* synthesis syn_maxfan=1000000 */,          //global reset input
    input bit           clkin, 
    input bit           clk200,         //200 MHz reference clock for IDELAYCTRL
    input bit           ring_clk,       //user clock
    input bit			ring_clk_nrdy,	//user clock not ready
	output bit			ring_rst,		//ring reset
    //RX/TX fifo interface
    output eth_rx_pipe_data_type rx_pipe,
    input  eth_tx_ring_data_type tx_ring,     
    
    // GMII Interface (1000 Base-T PHY interface)
    output bit [7:0]    GMII_TXD   /* synthesis syn_useioff=1 */,   
    output bit          GMII_TX_EN /* synthesis syn_useioff=1 */,
    output bit          GMII_TX_ER /* synthesis syn_useioff=1 */,
    output bit          GMII_TX_CLK, //to PHY. Made in ODDR
    input  bit [7:0]    GMII_RXD,
    input  bit          GMII_RX_DV,
    input  bit          GMII_RX_ER,
    input  bit          GMII_RX_CLK, //from PHY. Goes through BUFG
    output bit          GMII_RESET_B      
)/* synthesis syn_sharing=on */;
    
    localparam  FIFORSTSHIFTMSB = 31;
    
    //DCM internal signals
    bit            dfs_clkfx;
    bit [3:0]      dfs_rst_dly;
    
    //idelay signals
    bit [1:0]      ctrlLockx;
    bit            ctrlLock;
    
    //ethernet clocks
    bit            ethTXclock;                //The 125 MHz clock
    bit            ethRXclock;                //RX clock from PHY
    
    bit            TX_EN_FROM_MAC;
    bit            TX_ER_FROM_MAC;
    bit [7:0]      TXD_FROM_MAC;

    bit            RXclockDelay;
    bit [7:0]      RXdataDelay;
    (* syn_useioff=1 *) bit [7:0]      RXdataDelayReg ;
    bit            RXdvDelay, RXerDelay;
    (* syn_useioff=1 *) bit            RXdvDelayReg, RXerDelayReg;
    
    bit [15:0]     RXmacData;
    bit [7:0]      RXdata;
    bit            RXdataValid;
    bit            RXgoodFrame;
    bit            RXbadFrame;
     
    bit [7:0]      TXdata;       //data to MAC
    bit            TXdataValid;
    bit            TXack;
    
    //FIFO signals         
    bit            rx_fifo_we, rx_fifo_re, rx_fifo_empty;
    bit [35:0]     rx_fifo_din, rx_fifo_dout;
    bit [23:0]     rx_shf_data;
    bit [1:0]      rx_byte_count;    
    
    bit            tx_fifo_we, tx_fifo_re, tx_fifo_empty;
    bit [35:0]     tx_fifo_din, tx_fifo_dout;
    bit [3:0]      tx_byte_count; 
    bit            tx_byte_count_en, tx_byte_count_rst;
    
    //(* syn_srlstyle="select_srl" *) bit [FIFORSTSHIFTMSB:0] fifo_rst;
    bit            rst;
    
    //MAC header
    bit [7:0]     txheader[0:11], txheader_din;   
    bit			  txheader_we;
    
    //tx FSM
    enum bit [2:0] {tx_idle, tx_header, tx_update_header, tx_lt, tx_send} v_tx_state, r_tx_state;
    bit tx_first_byte,v_tx_first_byte;
    
    //GMII clock generation
    BUFG  eth_clkfx_buf(.O(ethTXclock), .I(dfs_clkfx));
    
    //eth ring reset signals
    (* syn_maxfan=1000000 *) bit eth_rst;
    bit [19:0] eth_rst_dly;
    
    always_ff @(posedge clkin or posedge reset) begin
      if (reset)
          dfs_rst_dly <= '1;
      else
          dfs_rst_dly <= dfs_rst_dly >> 1;                    //this shift register can be shared with other DCM modules
    end
  
    /*
    always_ff @(posedge ring_clk or posedge rst) begin
	    if (rst)
	    	eth_rst_dly <= '1;
	    else
	    	eth_rst_dly <= eth_rst_dly >> 1;
    end  
	*/
	bit dfs_locked;
	assign rst = reset | ring_clk_nrdy | ~dfs_locked;
	always_ff @(posedge ring_clk or posedge rst) begin
	    if (rst)
	    	eth_rst_dly <= {16'b1111, {4{~ring_clk_nrdy & dfs_locked}}};
	    else
	    	eth_rst_dly <= eth_rst_dly >> 1;
    end  
	
    BUFG eth_rst_buf(.O(eth_rst), .I(eth_rst_dly[0]));
    assign ring_rst = eth_rst; 
    
    generate
      if (CLKIN_PERIOD > 8.33)  
        DCM_BASE #(.CLKFX_MULTIPLY(CLKMUL),
             .CLKFX_DIVIDE(CLKDIV),
             .CLKDV_DIVIDE(2.0),
             .CLKIN_PERIOD(CLKIN_PERIOD),
             .CLK_FEEDBACK("NONE"),
             .DFS_FREQUENCY_MODE("LOW")) clk_dfs(
            .CLKIN(clkin),            
            .CLKFX(dfs_clkfx),
            .LOCKED(dfs_locked),	
            .RST(dfs_rst_dly[0]),
            //unconnected ports to suppress modelsim warnings
            .CLK0(),
            .CLKFB(),             //we don't care if this clock is phase aligned with clkin
            .CLK90(),
            .CLKDV(),
            .CLK180(),
            .CLK270(),
            .CLK2X(),
            .CLK2X180(),
            .CLKFX180()
          );		
      else
        DCM_BASE #(.CLKFX_MULTIPLY(CLKMUL),
             .CLKFX_DIVIDE(CLKDIV),
             .CLKDV_DIVIDE(2.0),
             .CLKIN_PERIOD(CLKIN_PERIOD),
             .CLK_FEEDBACK("NONE"),             
             .DFS_FREQUENCY_MODE("HIGH")) clk_dfs(
             .CLKIN(clkin),            
             .CLKFX(dfs_clkfx),
             .LOCKED(dfs_locked),	
             .RST(dfs_rst_dly[0]),
             //unconnected ports to suppress modelsim warnings
             .CLK0(),
             .CLKFB(),             //we don't care if this clock is phase aligned with clkin
             .CLK90(),
             .CLKDV(),
             .CLK180(),
             .CLK270(),
             .CLK2X(),
             .CLK2X180(),
             .CLKFX180() 
          );
    endgenerate 
    

    //------------------------------------------------------------------------
    // GMII Transmitter Logic : Drive TX signals through IOBs onto GMII
    // interface
    //------------------------------------------------------------------------
    // Infer IOB Output flip-flops.
    always @(posedge ethTXclock, posedge eth_rst)
    begin
      if (eth_rst == 1'b1)
      begin
        GMII_TX_EN <= 1'b0;
        GMII_TX_ER <= 1'b0;
        GMII_TXD   <= 8'h00;
      end
      else
      begin
        GMII_TX_EN <= TX_EN_FROM_MAC;
        GMII_TX_ER <= TX_ER_FROM_MAC;
        GMII_TXD   <= TXD_FROM_MAC;
      end
    end        

    assign GMII_RESET_B = ~eth_rst;
    
    //ODDR for Phy Clock
      ODDR #(.SRTYPE("ASYNC")) GMIIoddr (
          .Q(GMII_TX_CLK),.C(ethTXclock),.CE(1'b1),
          .D1(1'b0), .D2(1'b1), .R(eth_rst), .S(1'b0)
      );
    
    
    //IDELAYs and BUFG for the Receive data and clock
     IDELAY #(
        .IOBDELAY_TYPE("FIXED"), // "DEFAULT", "FIXED" or "VARIABLE"
        .IOBDELAY_VALUE(0) // Any value from 0 to 63
         ) RXclockBlk(
           .I(GMII_RX_CLK),.O(RXclockDelay),.C(1'b0),
          .CE(1'b0), .INC(1'b0),.RST(1'b0)
        );
    
      
      BUFG bufgClientRx (.I(RXclockDelay), .O(ethRXclock));
    
      IDELAY #(
        .IOBDELAY_TYPE("FIXED"), // "DEFAULT", "FIXED" or "VARIABLE"
        .IOBDELAY_VALUE(20) // Any value from 0 to 63
         ) RXdvBlock (
           .I(GMII_RX_DV), .O(RXdvDelay), .C(1'b0),
          .CE(1'b0), .INC(1'b0),.RST(1'b0)
        );

      IDELAY #(
        .IOBDELAY_TYPE("FIXED"), // "DEFAULT", "FIXED" or "VARIABLE"
        .IOBDELAY_VALUE(20) // Any value from 0 to 63
         ) RXerBlock (
           .I(GMII_RX_ER), .O(RXerDelay), .C(1'b0),
          .CE(1'b0), .INC(1'b0),.RST(1'b0)
        );
        
     genvar idly;
	 generate
      for(idly = 0; idly < 8; idly = idly + 1)
      begin: dlyBlock
         IDELAY #(
                .IOBDELAY_TYPE("FIXED"), // "DEFAULT", "FIXED" or "VARIABLE"
                .IOBDELAY_VALUE(20) // Any value from 0 to 63
                ) RXdataBlock
        (
           .I(GMII_RXD[idly]), .O(RXdataDelay[idly]), .C(1'b0),
           .CE(1'b0), .INC(1'b0),.RST(1'b0)
        );
      end
     endgenerate
  

    `ifndef SKIP_IDELAYCTRL_SIM         //don't want to simulate because this is unlikely wrong        
    //instantiate IDELAYCTRL
    assign ctrlLock = &ctrlLockx;
    
    generate
     case (BOARDSEL)
     default :	begin	//ML505/XUP
      //instantiate idelayctrls because of an ISE bug
       (* syn_noprune = 1, xc_loc="IDELAYCTRL_X0Y4" *) IDELAYCTRL idelayctrl0 (
        .RDY(ctrlLockx[0]),
        .REFCLK(clk200),
        .RST(eth_rst)
        );    
    
       (* syn_noprune = 1, xc_loc="IDELAYCTRL_X1Y5" *) IDELAYCTRL idelayctrl1 (
        .RDY(ctrlLockx[1]),
        .REFCLK(clk200),
        .RST(eth_rst)
        )/* synthesis xc_loc = "IDELAYCTRL_X0Y1" */;        
       end
     endcase                
     endgenerate
     `else
      assign ctrlLock = '1; 
     `endif
    
    always_ff @(posedge ethRXclock) begin  //register the delayed RXdata.
      RXdataDelayReg <= RXdataDelay;
      RXdvDelayReg <= RXdvDelay;
      RXerDelayReg <= RXerDelay;
    end

    //Instantiate RX and TX FIFO    
    //assign rst = fifo_rst[0];    
    //always_ff @(posedge clkin) fifo_rst <= {reset ,fifo_rst[FIFORSTSHIFTMSB:1]};     //wait for ring_clk to be stable    

    
    //rx fifo logic
    always_comb begin    
      //rx fifo signals
      rx_fifo_din[35:32] = {RXdataValid, RXbadFrame, rx_byte_count}; //tag bits in the EOF byte: EOF, Good/Bad frame, stop offset
      rx_fifo_din[31:0]  = {RXdata, rx_shf_data[23:0]};    
      
      rx_fifo_we = ((rx_byte_count == 3) & RXdataValid) | RXbadFrame | RXgoodFrame;
      rx_fifo_re = ~rx_fifo_empty;
      
      rx_pipe.stype    = (rx_fifo_empty) ?  rx_none : ((rx_fifo_dout[35]) ? rx_data : rx_end);
      rx_pipe.msg.data =  {rx_fifo_dout[31:1], (rx_fifo_dout[35]) ?  rx_fifo_dout[0] : rx_fifo_dout[34]};
    end
        
    
    always_ff @(posedge ethRXclock or posedge eth_rst) begin
      if (eth_rst) rx_byte_count <= '0;
      else if (~RXdataValid)
	      rx_byte_count <= '0;
	  else if (RXdataValid) 
        rx_byte_count <= rx_byte_count + 1;
     
	end
	
    always_ff @(posedge ethRXclock) begin
      if (RXdataValid & rx_byte_count !=3)
        rx_shf_data <= {RXdata, rx_shf_data[23:8]};
    end
    
    //fifo reset

    
    FIFO18_36 #(
    .DO_REG(1),       // Enable output register (0 or 1)
    .EN_SYN("FALSE"), // Specifies FIFO as Asynchronous ("FALSE")
    .FIRST_WORD_FALL_THROUGH("TRUE") // Sets the FIFO FWFT to "TRUE" or "FALSE"
    ) rxfifo (
    .ALMOSTEMPTY(), 
    .ALMOSTFULL(), 
    .DO(rx_fifo_dout[31:0]), 
    .DOP(rx_fifo_dout[35:32]), 
    .EMPTY(rx_fifo_empty), 
    .FULL(), 
    .RDCOUNT(), 
    .RDERR(), 
    .WRCOUNT(), 
    .WRERR(), // 1-bit write error
    .DI(rx_fifo_din[31:0]), // 32-bit data input
    .DIP(rx_fifo_din[35:32]), // 4-bit parity input
    .RDCLK(ring_clk), // 1-bit read clock input
    .RDEN(rx_fifo_re), // 1-bit read enable input
    .RST(eth_rst), // 1-bit reset input
    .WRCLK(ethRXclock), // 1-bit write clock input
    .WREN(rx_fifo_we) // 1-bit write enable input
    );
    
    //tx fifo logic
    always_comb begin
      tx_fifo_din[31:0] = tx_ring.msg.data;
      tx_fifo_din[35:32] = unsigned'(tx_ring.stype);
      tx_fifo_we = (tx_ring.stype == tx_start ||  tx_ring.stype == slot_start || tx_ring.stype == slot_data) ? 1'b1 : 1'b0;
      
      v_tx_state = r_tx_state;
      tx_byte_count_en = '0;
      tx_byte_count_rst = '0;
      tx_fifo_re = (tx_byte_count[1:0] == 2'b11) ? ~tx_fifo_empty : '0;
                 
      case (tx_byte_count[1:0])
       2'b00: txheader_din = tx_fifo_dout[7:0];
       2'b01: txheader_din = tx_fifo_dout[15:8];
       2'b10: txheader_din = tx_fifo_dout[23:16];
       2'b11: txheader_din = tx_fifo_dout[31:24];
      endcase  
      
      TXdata = txheader_din;
      TXdataValid = ~tx_fifo_empty;
      
      txheader_we = '0;
      
      v_tx_first_byte = tx_first_byte;

      unique case(r_tx_state)
      tx_idle : begin
                  tx_fifo_re = (tx_fifo_dout[34:32] == tx_start) ? '1 : '0;     //strip out the header
                  tx_byte_count_rst = '1;                  
                  TXdataValid = '0;

                  if (~tx_fifo_empty) 
                     v_tx_state = (tx_fifo_dout[34:32] == tx_start) ? tx_update_header : tx_header;
                end
      tx_header : begin
                    tx_byte_count_en = '1;
                    txheader_we = '1;
                    tx_fifo_re  = '0;

                    if (tx_byte_count == 0) begin
                      tx_byte_count_en = TXack;
                      txheader_we = TXack;
                    end

                    TXdata = txheader[0];
                    txheader_din = txheader[0];
                    
                    if (tx_byte_count == 11) 
                      v_tx_state = tx_lt;
                end
      tx_update_header : begin 
                      tx_byte_count_en = '1;
                      txheader_we = '1;

                      if (tx_byte_count == 0) begin
                        tx_byte_count_en = TXack;
                        txheader_we = TXack;
                      end

                      TXdata = txheader_din;                      
                      
                      if (tx_byte_count == 11) 
                        v_tx_state = tx_lt;                            
                  end
      tx_lt : begin
                tx_byte_count_en = '1;      
                tx_fifo_re = '0;          
                
                unique case (tx_byte_count[1:0])
                 2'b00: TXdata = protocolTypeRAMP[7:0];
                 2'b01: TXdata = protocolTypeRAMP[15:8];
                 2'b10: TXdata = '0;
                 2'b11: begin TXdata = '0; v_tx_state = tx_send; end
                endcase  
                
                v_tx_first_byte = '1;
              end
      default : begin     //tx_send
                  tx_byte_count_en = '1;                
            
                  if (tx_fifo_empty) begin
                    tx_byte_count_rst = '1;
                    TXdataValid = '0;
                    v_tx_state = tx_idle;
                    tx_fifo_re = '0;
                  end
                  else if (tx_fifo_dout[34:32] == slot_start && tx_first_byte == 0) begin
                    tx_byte_count_rst = '1;
                    TXdataValid = '0;
                    v_tx_state = tx_header;
                    tx_fifo_re = '0;
                  end
                  else if (tx_fifo_dout[34:32] == tx_start) begin
                    tx_byte_count_rst = '1;
                    TXdataValid = '0;
                    v_tx_state = tx_update_header;
                    tx_fifo_re = '1;      //strip the header
                  end                
                  
                  if (tx_byte_count[1:0] == 2'b11)
                    v_tx_first_byte = '0;                                                      
                end
      endcase      
    end

    always_ff @(posedge ethTXclock or posedge eth_rst) begin     
	  if (eth_rst) tx_byte_count <= '0;
      else if (tx_byte_count_rst) tx_byte_count <= '0;
      else if (tx_byte_count_en) tx_byte_count <= tx_byte_count + 1;
        
      if (eth_rst) r_tx_state <= tx_idle;
      else r_tx_state <= v_tx_state;     
	end
	
	always_ff @(posedge ethTXclock) begin
      if (txheader_we) begin
        txheader <= {txheader[1:11], txheader_din};
      end   
      
       tx_first_byte <= v_tx_first_byte;
    end
    
    FIFO36 #(
    .DATA_WIDTH(36),
    .DO_REG(1),       // Enable output register (0 or 1)
    .EN_SYN("FALSE"), // Specifies FIFO as Asynchronous ("FALSE")
    .FIRST_WORD_FALL_THROUGH("TRUE") // Sets the FIFO FWFT to "TRUE" or "FALSE"
    ) txfifo (
    .ALMOSTEMPTY(), 
    .ALMOSTFULL(), 
    .DO(tx_fifo_dout[31:0]), 
    .DOP(tx_fifo_dout[35:32]), 
    .EMPTY(tx_fifo_empty), 
    .FULL(), 
    .RDCOUNT(), 
    .RDERR(), 
    .WRCOUNT(), 
    .WRERR(), // 1-bit write error
    .DI(tx_fifo_din[31:0]), // 32-bit data input
    .DIP(tx_fifo_din[35:32]), // 4-bit parity input
    .RDCLK(ethTXclock), // 1-bit read clock input
    .RDEN(tx_fifo_re), // 1-bit read enable input
    .RST(eth_rst), // 1-bit reset input
    .WRCLK(ring_clk), // 1-bit write clock input
    .WREN(tx_fifo_we) // 1-bit write enable input
    );
    
    
    //--------------------------------------------------------------------------
    // Instantiate the Virtex-5 Embedded Ethernet EMAC
    //--------------------------------------------------------------------------
    assign RXdata = RXmacData[7:0];  //TEMAC has a 16-bit interface

    TEMAC v5_emac
    (
        .RESET                          (eth_rst),

        // EMAC0
        .EMAC0CLIENTRXCLIENTCLKOUT      (),
        .CLIENTEMAC0RXCLIENTCLKIN       (ethRXclock),
        .EMAC0CLIENTRXD                 (RXmacData),
        .EMAC0CLIENTRXDVLD              (RXdataValid),
        .EMAC0CLIENTRXDVLDMSW           (),
        .EMAC0CLIENTRXGOODFRAME         (RXgoodFrame),
        .EMAC0CLIENTRXBADFRAME          (RXbadFrame),
        .EMAC0CLIENTRXFRAMEDROP         (),
        .EMAC0CLIENTRXSTATS             (),
        .EMAC0CLIENTRXSTATSVLD          (),
        .EMAC0CLIENTRXSTATSBYTEVLD      (),

        .EMAC0CLIENTTXCLIENTCLKOUT      (),
        .CLIENTEMAC0TXCLIENTCLKIN       (ethTXclock),
        .CLIENTEMAC0TXD                 ({8'h0,TXdata}),
        .CLIENTEMAC0TXDVLD              (TXdataValid),
        .CLIENTEMAC0TXDVLDMSW           (1'b0),
        .EMAC0CLIENTTXACK               (TXack),
        .CLIENTEMAC0TXFIRSTBYTE         (1'b0),
        .CLIENTEMAC0TXUNDERRUN          (1'b0),
        .EMAC0CLIENTTXCOLLISION         (),
        .EMAC0CLIENTTXRETRANSMIT        (),
        .CLIENTEMAC0TXIFGDELAY          (),
        .EMAC0CLIENTTXSTATS             (),
        .EMAC0CLIENTTXSTATSVLD          (),
        .EMAC0CLIENTTXSTATSBYTEVLD      (),

        .CLIENTEMAC0PAUSEREQ            (1'b0),                 //no flow control now
        .CLIENTEMAC0PAUSEVAL            (16'b0),

        .PHYEMAC0GTXCLK                 (1'b0),
        .EMAC0PHYTXGMIIMIICLKOUT        (),
        .PHYEMAC0TXGMIIMIICLKIN         (ethTXclock),

        .PHYEMAC0RXCLK                  (ethRXclock),
        .PHYEMAC0RXD                    (RXdataDelayReg),
        .PHYEMAC0RXDV                   (RXdvDelayReg),
        .PHYEMAC0RXER                   (RXerDelayReg),
        .EMAC0PHYTXCLK                  (),
        .EMAC0PHYTXD                    (TXD_FROM_MAC),
        .EMAC0PHYTXEN                   (TX_EN_FROM_MAC),
        .EMAC0PHYTXER                   (TX_ER_FROM_MAC),
        .PHYEMAC0MIITXCLK               (1'b0),
        .PHYEMAC0COL                    (1'b0),
        .PHYEMAC0CRS                    (1'b0),

        .CLIENTEMAC0DCMLOCKED           (ctrlLock),
        .EMAC0CLIENTANINTERRUPT         (),
        .PHYEMAC0SIGNALDET              (1'b0),
        .PHYEMAC0PHYAD                  (5'b00000),
        .EMAC0PHYENCOMMAALIGN           (),
        .EMAC0PHYLOOPBACKMSB            (),
        .EMAC0PHYMGTRXRESET             (),
        .EMAC0PHYMGTTXRESET             (),
        .EMAC0PHYPOWERDOWN              (),
        .EMAC0PHYSYNCACQSTATUS          (),
        .PHYEMAC0RXCLKCORCNT            (3'b000),
        .PHYEMAC0RXBUFSTATUS            (2'b00),
        .PHYEMAC0RXBUFERR               (1'b0),
        .PHYEMAC0RXCHARISCOMMA          (1'b0),
        .PHYEMAC0RXCHARISK              (1'b0),
        .PHYEMAC0RXCHECKINGCRC          (1'b0),
        .PHYEMAC0RXCOMMADET             (1'b0),
        .PHYEMAC0RXDISPERR              (1'b0),
        .PHYEMAC0RXLOSSOFSYNC           (2'b00),
        .PHYEMAC0RXNOTINTABLE           (1'b0),
        .PHYEMAC0RXRUNDISP              (1'b0),
        .PHYEMAC0TXBUFERR               (1'b0),
        .EMAC0PHYTXCHARDISPMODE         (),
        .EMAC0PHYTXCHARDISPVAL          (),
        .EMAC0PHYTXCHARISK              (),

        .EMAC0PHYMCLKOUT                (),
        .PHYEMAC0MCLKIN                 (1'b0),
        .PHYEMAC0MDIN                   (1'b1),
        .EMAC0PHYMDOUT                  (),
        .EMAC0PHYMDTRI                  (),
        .EMAC0SPEEDIS10100              (),

        // EMAC1
        .EMAC1CLIENTRXCLIENTCLKOUT      (),
        .CLIENTEMAC1RXCLIENTCLKIN       (1'b0),
        .EMAC1CLIENTRXD                 (),
        .EMAC1CLIENTRXDVLD              (),
        .EMAC1CLIENTRXDVLDMSW           (),
        .EMAC1CLIENTRXGOODFRAME         (),
        .EMAC1CLIENTRXBADFRAME          (),
        .EMAC1CLIENTRXFRAMEDROP         (),
        .EMAC1CLIENTRXSTATS             (),
        .EMAC1CLIENTRXSTATSVLD          (),
        .EMAC1CLIENTRXSTATSBYTEVLD      (),

        .EMAC1CLIENTTXCLIENTCLKOUT      (),
        .CLIENTEMAC1TXCLIENTCLKIN       (1'b0),
        .CLIENTEMAC1TXD                 (16'h0000),
        .CLIENTEMAC1TXDVLD              (1'b0),
        .CLIENTEMAC1TXDVLDMSW           (1'b0),
        .EMAC1CLIENTTXACK               (),
        .CLIENTEMAC1TXFIRSTBYTE         (1'b0),
        .CLIENTEMAC1TXUNDERRUN          (1'b0),
        .EMAC1CLIENTTXCOLLISION         (),
        .EMAC1CLIENTTXRETRANSMIT        (),
        .CLIENTEMAC1TXIFGDELAY          (8'h00),
        .EMAC1CLIENTTXSTATS             (),
        .EMAC1CLIENTTXSTATSVLD          (),
        .EMAC1CLIENTTXSTATSBYTEVLD      (),

        .CLIENTEMAC1PAUSEREQ            (1'b0),
        .CLIENTEMAC1PAUSEVAL            (16'h0000),

        .PHYEMAC1GTXCLK                 (1'b0),
        .EMAC1PHYTXGMIIMIICLKOUT        (),
        .PHYEMAC1TXGMIIMIICLKIN         (1'b0),

        .PHYEMAC1RXCLK                  (1'b0),
        .PHYEMAC1RXD                    (8'h00),
        .PHYEMAC1RXDV                   (1'b0),
        .PHYEMAC1RXER                   (1'b0),
        .PHYEMAC1MIITXCLK               (1'b0),
        .EMAC1PHYTXCLK                  (),
        .EMAC1PHYTXD                    (),
        .EMAC1PHYTXEN                   (),
        .EMAC1PHYTXER                   (),
        .PHYEMAC1COL                    (1'b0),
        .PHYEMAC1CRS                    (1'b0),

        .CLIENTEMAC1DCMLOCKED           (1'b1),
        .EMAC1CLIENTANINTERRUPT         (),
        .PHYEMAC1SIGNALDET              (1'b0),
        .PHYEMAC1PHYAD                  (5'b00000),
        .EMAC1PHYENCOMMAALIGN           (),
        .EMAC1PHYLOOPBACKMSB            (),
        .EMAC1PHYMGTRXRESET             (),
        .EMAC1PHYMGTTXRESET             (),
        .EMAC1PHYPOWERDOWN              (),
        .EMAC1PHYSYNCACQSTATUS          (),
        .PHYEMAC1RXCLKCORCNT            (3'b000),
        .PHYEMAC1RXBUFSTATUS            (2'b00),
        .PHYEMAC1RXBUFERR               (1'b0),
        .PHYEMAC1RXCHARISCOMMA          (1'b0),
        .PHYEMAC1RXCHARISK              (1'b0),
        .PHYEMAC1RXCHECKINGCRC          (1'b0),
        .PHYEMAC1RXCOMMADET             (1'b0),
        .PHYEMAC1RXDISPERR              (1'b0),
        .PHYEMAC1RXLOSSOFSYNC           (2'b00),
        .PHYEMAC1RXNOTINTABLE           (1'b0),
        .PHYEMAC1RXRUNDISP              (1'b0),
        .PHYEMAC1TXBUFERR               (1'b0),
        .EMAC1PHYTXCHARDISPMODE         (),
        .EMAC1PHYTXCHARDISPVAL          (),
        .EMAC1PHYTXCHARISK              (),

        .EMAC1PHYMCLKOUT                (),
        .PHYEMAC1MCLKIN                 (1'b0),
        .PHYEMAC1MDIN                   (1'b0),
        .EMAC1PHYMDOUT                  (),
        .EMAC1PHYMDTRI                  (),
        .EMAC1SPEEDIS10100              (),

        // Host Interface 
        .HOSTCLK                        (1'b0),
        .HOSTOPCODE                     (2'b00),
        .HOSTREQ                        (1'b0),
        .HOSTMIIMSEL                    (1'b0),
        .HOSTADDR                       (10'b0000000000),
        .HOSTWRDATA                     (32'h00000000),
        .HOSTMIIMRDY                    (),
        .HOSTRDDATA                     (),
        .HOSTEMAC1SEL                   (1'b0),

        // DCR Interface
        .DCREMACCLK                     (1'b0),
        .DCREMACABUS                    (10'h000),
        .DCREMACREAD                    (1'b0),
        .DCREMACWRITE                   (1'b0),
        .DCREMACDBUS                    (32'h00000000),
        .EMACDCRACK                     (),
        .EMACDCRDBUS                    (),
        .DCREMACENABLE                  (1'b0),
        .DCRHOSTDONEIR                  ()
    );
    defparam v5_emac.EMAC0_PHYINITAUTONEG_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_PHYISOLATE = "FALSE";
    defparam v5_emac.EMAC0_PHYLOOPBACKMSB = "FALSE";
    defparam v5_emac.EMAC0_PHYPOWERDOWN = "FALSE";
    defparam v5_emac.EMAC0_PHYRESET = "TRUE";
    defparam v5_emac.EMAC0_CONFIGVEC_79 = "FALSE";
    defparam v5_emac.EMAC0_GTLOOPBACK = "FALSE";
    defparam v5_emac.EMAC0_UNIDIRECTION_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_LINKTIMERVAL = 9'h000;
    defparam v5_emac.EMAC0_MDIO_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_SPEED_LSB = "FALSE";
    defparam v5_emac.EMAC0_SPEED_MSB = "TRUE"; 
    defparam v5_emac.EMAC0_USECLKEN = "FALSE";
    defparam v5_emac.EMAC0_BYTEPHY = "FALSE";
    defparam v5_emac.EMAC0_RGMII_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_SGMII_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_1000BASEX_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_HOST_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_TX16BITCLIENT_ENABLE = "FALSE";
    defparam v5_emac.EMAC0_RX16BITCLIENT_ENABLE = "FALSE";    
    defparam v5_emac.EMAC0_ADDRFILTER_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_LTCHECK_DISABLE = "FALSE";  
    defparam v5_emac.EMAC0_RXFLOWCTRL_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_TXFLOWCTRL_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_TXRESET = "FALSE";  
    defparam v5_emac.EMAC0_TXJUMBOFRAME_ENABLE = "TRUE";            //support jumbo frame
    defparam v5_emac.EMAC0_TXINBANDFCS_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_TX_ENABLE = "TRUE";  
    defparam v5_emac.EMAC0_TXVLAN_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_TXHALFDUPLEX = "FALSE";  
    defparam v5_emac.EMAC0_TXIFGADJUST_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_RXRESET = "FALSE";  
    defparam v5_emac.EMAC0_RXJUMBOFRAME_ENABLE = "TRUE";           //support jumbo frame
    defparam v5_emac.EMAC0_RXINBANDFCS_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_RX_ENABLE = "TRUE";  
    defparam v5_emac.EMAC0_RXVLAN_ENABLE = "FALSE";  
    defparam v5_emac.EMAC0_RXHALFDUPLEX = "FALSE";  
    defparam v5_emac.EMAC0_PAUSEADDR = 48'hFFEEDDCCBBAA;
    defparam v5_emac.EMAC0_UNICASTADDR = 48'h000000000000;
    defparam v5_emac.EMAC0_DCRBASEADDR = 8'h00;

endmodule