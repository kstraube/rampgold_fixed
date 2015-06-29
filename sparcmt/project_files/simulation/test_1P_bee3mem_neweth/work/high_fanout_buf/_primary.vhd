library verilog;
use verilog.vl_types.all;
entity high_fanout_buf is
    generic(
        fpgatech        : vl_notype
    );
    port(
        gin             : in     vl_logic;
        gout            : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end high_fanout_buf;
