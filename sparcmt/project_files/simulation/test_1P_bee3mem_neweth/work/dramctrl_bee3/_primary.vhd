library verilog;
use verilog.vl_types.all;
library work;
entity dramctrl_bee3 is
    generic(
        REFRESHINHIBIT  : vl_logic := Hi1;
        SINGLEMODULE    : vl_logic := Hi1;
        WRITEECC        : string  := "TRUE";
        no_ecc_data_path: string  := "FALSE"
    );
    port(
        ram_clk         : in     work.libtech.dram_clk_type;
        DQ              : inout  vl_logic_vector(71 downto 0);
        DQS             : inout  vl_logic_vector(17 downto 0);
        DQS_L           : inout  vl_logic_vector(17 downto 0);
        DIMMCK          : out    vl_logic_vector(1 downto 0);
        DIMMCKL         : out    vl_logic_vector(1 downto 0);
        DIMMreset       : out    vl_logic;
        A               : out    vl_logic_vector(13 downto 0);
        BA              : out    vl_logic_vector(2 downto 0);
        RAS             : out    vl_logic;
        CAS             : out    vl_logic;
        WE              : out    vl_logic;
        ODT             : out    vl_logic_vector(1 downto 0);
        ClkEn           : out    vl_logic;
        RS              : out    vl_logic_vector(3 downto 0);
        TxD             : out    vl_logic;
        RxD             : in     vl_logic;
        SingleError     : out    vl_logic;
        DoubleError     : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of REFRESHINHIBIT : constant is 2;
    attribute mti_svvh_generic_type of SINGLEMODULE : constant is 2;
    attribute mti_svvh_generic_type of WRITEECC : constant is 1;
    attribute mti_svvh_generic_type of no_ecc_data_path : constant is 1;
end dramctrl_bee3;
