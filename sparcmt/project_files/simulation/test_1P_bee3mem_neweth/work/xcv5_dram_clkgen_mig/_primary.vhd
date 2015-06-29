library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_dram_clkgen_mig is
    generic(
        CLKMUL          : integer := 8;
        CLKDIV          : integer := 3;
        CLKDIV200       : integer := 4;
        CLKIN_PERIOD    : real    := 10.000000
    );
    port(
        clkin           : in     vl_logic;
        rstin           : in     vl_logic;
        dramrst         : in     vl_logic;
        ram_clk         : out    work.libtech.dram_clk_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of CLKMUL : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV200 : constant is 1;
    attribute mti_svvh_generic_type of CLKIN_PERIOD : constant is 1;
end xcv5_dram_clkgen_mig;
