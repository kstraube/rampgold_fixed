library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_icache_ram_wide is
    generic(
        tagprot         : integer := 1;
        dataprot        : integer := 2;
        NONECCDRAM      : string  := "TRUE";
        ECCSCRUB        : string  := "FALSE"
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu_in           : in     work.libcache.cache_ram_in_type;
        iu_out          : out    work.libcache.cache_ram_out_type;
        mem_in          : in     work.libcache.cache_ram_wide_in_type;
        mem_out         : out    work.libcache.cache_ram_wide_out_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of tagprot : constant is 2;
    attribute mti_svvh_generic_type of dataprot : constant is 2;
    attribute mti_svvh_generic_type of NONECCDRAM : constant is 1;
    attribute mti_svvh_generic_type of ECCSCRUB : constant is 1;
end xcv5_icache_ram_wide;
