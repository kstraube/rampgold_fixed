library verilog;
use verilog.vl_types.all;
entity flight_recorder is
    generic(
        DWIDTH          : integer := 72
    );
    port(
        clk             : in     vl_logic;
        rst             : in     vl_logic;
        din             : in     vl_logic_vector;
        dout            : out    vl_logic_vector
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DWIDTH : constant is 1;
end flight_recorder;
