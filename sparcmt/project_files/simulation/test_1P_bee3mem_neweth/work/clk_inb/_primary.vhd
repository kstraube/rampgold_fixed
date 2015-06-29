library verilog;
use verilog.vl_types.all;
entity clk_inb is
    generic(
        fpgatech        : vl_notype;
        differential    : integer := 1
    );
    port(
        clk_n           : in     vl_logic;
        clk_p           : in     vl_logic;
        clk             : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
    attribute mti_svvh_generic_type of differential : constant is 1;
end clk_inb;
