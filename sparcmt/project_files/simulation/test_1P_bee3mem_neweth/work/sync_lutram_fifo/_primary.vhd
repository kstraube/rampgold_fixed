library verilog;
use verilog.vl_types.all;
entity sync_lutram_fifo is
    generic(
        DWIDTH          : integer := 1;
        DEPTH           : integer := 64;
        DOREG           : vl_logic := Hi1
    );
    port(
        clk             : in     vl_logic;
        rst             : in     vl_logic;
        din             : in     vl_logic_vector;
        we              : in     vl_logic;
        re              : in     vl_logic;
        empty           : out    vl_logic;
        full            : out    vl_logic;
        dout            : out    vl_logic_vector
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DWIDTH : constant is 1;
    attribute mti_svvh_generic_type of DEPTH : constant is 1;
    attribute mti_svvh_generic_type of DOREG : constant is 2;
end sync_lutram_fifo;
