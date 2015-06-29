library verilog;
use verilog.vl_types.all;
library work;
entity clkrst_gen_2 is
    generic(
        differential    : integer := 1;
        nocebuf         : integer := 0;
        fpgatech        : vl_notype;
        IMPL_IBUFG      : integer := 1;
        BOARDSEL        : integer := 1
    );
    port(
        clkin_p         : in     vl_logic;
        clkin_n         : in     vl_logic;
        rstin           : in     vl_logic;
        clk200          : in     vl_logic;
        cpurst          : in     vl_logic;
        dramrst         : in     vl_logic;
        gclk            : out    work.libiu.iu_clk_type;
        ram_clk         : out    work.libtech.dram_clk_type;
        rst             : out    vl_logic;
        clkin_b         : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of differential : constant is 1;
    attribute mti_svvh_generic_type of nocebuf : constant is 1;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
    attribute mti_svvh_generic_type of IMPL_IBUFG : constant is 1;
    attribute mti_svvh_generic_type of BOARDSEL : constant is 1;
end clkrst_gen_2;
