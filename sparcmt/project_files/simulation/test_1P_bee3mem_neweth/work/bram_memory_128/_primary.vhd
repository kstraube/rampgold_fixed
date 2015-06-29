library verilog;
use verilog.vl_types.all;
library work;
entity bram_memory_128 is
    generic(
        dataprot        : integer := 2;
        ADDRMSB         : integer := 8;
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        addr            : in     vl_logic_vector;
        we              : in     vl_logic;
        din             : in     work.libcache.cache_data_type;
        dout            : out    work.libcache.cache_data_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of dataprot : constant is 2;
    attribute mti_svvh_generic_type of ADDRMSB : constant is 2;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end bram_memory_128;
