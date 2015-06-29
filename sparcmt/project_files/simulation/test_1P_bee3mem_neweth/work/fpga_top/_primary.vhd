library verilog;
use verilog.vl_types.all;
entity fpga_top is
    port(
        clkin_p         : in     vl_logic;
        clkin_n         : in     vl_logic;
        clk200_p        : in     vl_logic;
        clk200_n        : in     vl_logic;
        rstin           : in     vl_logic;
        cpurst          : in     vl_logic;
        RxD             : in     vl_logic;
        TxD             : out    vl_logic;
        ddr2_dq         : inout  vl_logic_vector(63 downto 0);
        ddr2_a          : out    vl_logic_vector(13 downto 0);
        ddr2_ba         : out    vl_logic_vector(2 downto 0);
        ddr2_ras_n      : out    vl_logic;
        ddr2_cas_n      : out    vl_logic;
        ddr2_we_n       : out    vl_logic;
        ddr2_cs_n       : out    vl_logic_vector(1 downto 0);
        ddr2_odt        : out    vl_logic_vector(1 downto 0);
        ddr2_cke        : out    vl_logic_vector(1 downto 0);
        ddr2_dm         : out    vl_logic_vector(7 downto 0);
        ddr2_dqs        : inout  vl_logic_vector(7 downto 0);
        ddr2_dqs_n      : inout  vl_logic_vector(7 downto 0);
        ddr2_ck         : out    vl_logic_vector(1 downto 0);
        ddr2_ck_n       : out    vl_logic_vector(1 downto 0);
        error1_led      : out    vl_logic;
        error2_led      : out    vl_logic;
        PHY_TXD         : out    vl_logic_vector(7 downto 0);
        PHY_TXEN        : out    vl_logic;
        PHY_TXER        : out    vl_logic;
        PHY_GTXCLK      : out    vl_logic;
        PHY_RXD         : in     vl_logic_vector(7 downto 0);
        PHY_RXDV        : in     vl_logic;
        PHY_RXER        : in     vl_logic;
        PHY_RXCLK       : in     vl_logic;
        PHY_RESET       : out    vl_logic
    );
end fpga_top;
