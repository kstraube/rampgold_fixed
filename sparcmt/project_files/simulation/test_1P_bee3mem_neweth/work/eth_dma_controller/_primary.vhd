library verilog;
use verilog.vl_types.all;
library work;
entity eth_dma_controller is
    generic(
        CLKMUL          : integer := 5;
        CLKDIV          : integer := 4;
        CLKIN_PERIOD    : real    := 10.000000;
        BOARDSEL        : integer := 1
    );
    port(
        reset           : in     vl_logic;
        clkin           : in     vl_logic;
        clk200          : in     vl_logic;
        gclk            : in     work.libiu.iu_clk_type;
        eth_rst         : out    vl_logic;
        rx_pipe_out     : out    work.libeth.eth_rx_pipe_data_type;
        tx_ring_in      : in     work.libeth.eth_tx_ring_data_type;
        tx_ring_out     : out    work.libeth.eth_tx_ring_data_type;
        GMII_TXD        : out    vl_logic_vector(7 downto 0);
        GMII_TX_EN      : out    vl_logic;
        GMII_TX_ER      : out    vl_logic;
        GMII_TX_CLK     : out    vl_logic;
        GMII_RXD        : in     vl_logic_vector(7 downto 0);
        GMII_RX_DV      : in     vl_logic;
        GMII_RX_ER      : in     vl_logic;
        GMII_RX_CLK     : in     vl_logic;
        GMII_RESET_B    : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of CLKMUL : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV : constant is 1;
    attribute mti_svvh_generic_type of CLKIN_PERIOD : constant is 1;
    attribute mti_svvh_generic_type of BOARDSEL : constant is 1;
end eth_dma_controller;
