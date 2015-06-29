library verilog;
use verilog.vl_types.all;
library work;
entity replay_fifo is
    generic(
        DEPTH           : integer := 64;
        WIDTH           : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        enq             : in     vl_logic;
        enq_data        : in     vl_logic_vector;
        deq             : in     vl_logic;
        head            : out    vl_logic_vector;
        empty           : out    vl_logic;
        full            : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DEPTH : constant is 1;
    attribute mti_svvh_generic_type of WIDTH : constant is 3;
end replay_fifo;
