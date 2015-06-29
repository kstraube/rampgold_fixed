library verilog;
use verilog.vl_types.all;
entity gated_clkbuf is
    generic(
        fpgatech        : vl_notype;
        disablehigh     : integer := 1
    );
    port(
        clk_in          : in     vl_logic;
        clk_ce          : in     vl_logic;
        clk_out         : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
    attribute mti_svvh_generic_type of disablehigh : constant is 1;
end gated_clkbuf;
