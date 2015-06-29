library verilog;
use verilog.vl_types.all;
entity xcv5_cpu_clkgen is
    generic(
        CLKMUL          : real    := 2.000000;
        CLKDIV          : real    := 2.000000;
        CLKIN_PERIOD    : real    := 10.000000
    );
    port(
        clkin           : in     vl_logic;
        rstin           : in     vl_logic;
        clk             : out    vl_logic;
        clk2x           : out    vl_logic;
        ce              : out    vl_logic;
        locked          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of CLKMUL : constant is 1;
    attribute mti_svvh_generic_type of CLKDIV : constant is 1;
    attribute mti_svvh_generic_type of CLKIN_PERIOD : constant is 1;
end xcv5_cpu_clkgen;
