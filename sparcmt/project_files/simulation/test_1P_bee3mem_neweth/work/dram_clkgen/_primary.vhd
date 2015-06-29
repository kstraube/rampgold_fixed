library verilog;
use verilog.vl_types.all;
library work;
entity dram_clkgen is
    generic(
        fpgatech        : vl_notype;
        CLKMUL          : real    := 8.000000;
        CLKDIV          : real    := 3.000000;
        CLKIN_PERIOD    : real    := 10.000000;
        CLKDIV200       : real    := 3.000000;
        BOARDSEL        : integer := 1
    );
    port(
        clkin           : in     vl_logic;
        rstin           : in     vl_logic;
        dramrst         : in     vl_logic;
        clk200          : in     vl_logic;
        ram_clk         : out    work.libtech.dram_clk_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
    attribute mti_svvh_generic_type of CLKMUL : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV : constant is 1;
    attribute mti_svvh_generic_type of CLKIN_PERIOD : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV200 : constant is 1;
    attribute mti_svvh_generic_type of BOARDSEL : constant is 1;
end dram_clkgen;
