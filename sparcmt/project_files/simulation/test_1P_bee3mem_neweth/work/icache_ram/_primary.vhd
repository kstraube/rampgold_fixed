library verilog;
use verilog.vl_types.all;
library work;
entity icache_ram is
    generic(
        tagprot         : integer := 1;
        dataprot        : integer := 2;
        read2x          : integer := 0;
        write2x         : integer := 0;
        NONECCDRAM      : string  := "TRUE";
        ECCSCRUB        : string  := "FALSE";
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu_in           : in     work.libcache.cache_ram_in_type;
        iu_out          : out    work.libcache.cache_ram_out_type;
        mem_in          : in     work.libcache.cache_ram_in_type;
        mem_out         : out    work.libcache.cache_ram_out_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of tagprot : constant is 2;
    attribute mti_svvh_generic_type of dataprot : constant is 2;
    attribute mti_svvh_generic_type of read2x : constant is 2;
    attribute mti_svvh_generic_type of write2x : constant is 2;
    attribute mti_svvh_generic_type of NONECCDRAM : constant is 1;
    attribute mti_svvh_generic_type of ECCSCRUB : constant is 1;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end icache_ram;
