library verilog;
use verilog.vl_types.all;
entity sh_reg is
    generic(
        WIDTH           : integer := 16;
        DEPTH           : integer := 4
    );
    port(
        clk             : in     vl_logic;
        din             : in     vl_logic_vector;
        dout            : out    vl_logic_vector
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of WIDTH : constant is 1;
    attribute mti_svvh_generic_type of DEPTH : constant is 1;
end sh_reg;
