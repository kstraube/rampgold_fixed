library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_dram_clkgen_bee3 is
    generic(
        CLKMUL          : integer := 8;
        CLKDIV          : integer := 3;
        PLLDIV          : integer := 1;
        CLKIN_PERIOD    : real    := 10.000000;
        BOARDSEL        : integer := 1
    );
    port(
        clkin           : in     vl_logic;
        rstin           : in     vl_logic;
        clk200          : in     vl_logic;
        ram_clk         : out    work.libtech.dram_clk_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of CLKMUL : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV : constant is 1;
    attribute mti_svvh_generic_type of PLLDIV : constant is 1;
    attribute mti_svvh_generic_type of CLKIN_PERIOD : constant is 1;
    attribute mti_svvh_generic_type of BOARDSEL : constant is 1;
end xcv5_dram_clkgen_bee3;
