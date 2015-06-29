library verilog;
use verilog.vl_types.all;
library work;
entity tag_ram is
    generic(
        DEPTH           : integer := 8;
        WIDTH           : integer := 32
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        read_addr       : in     vl_logic_vector;
        read_data       : out    vl_logic_vector;
        write_addr      : in     vl_logic_vector;
        write_data      : in     vl_logic_vector;
        write_en        : in     vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DEPTH : constant is 1;
    attribute mti_svvh_generic_type of WIDTH : constant is 1;
end tag_ram;
