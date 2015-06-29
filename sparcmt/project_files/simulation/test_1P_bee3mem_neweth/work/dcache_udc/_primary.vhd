library verilog;
use verilog.vl_types.all;
library work;
entity dcache_udc is
    generic(
        CACHEDATAPROT   : integer := 2;
        AUTORECOVER     : integer := 0;
        read2x          : integer := 0;
        write2x         : integer := 0;
        MMUREFBIT       : integer := 0;
        MMUDIRTYBIT     : integer := 0;
        NONECCDRAM      : string  := "FALSE"
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        mem2iu_stat     : in     work.libmemif.mem_stat_out_type;
        iu2mem_tid      : out    vl_logic_vector;
        iu2mem_cmd      : out    work.libmemif.mem_cmd_in_type;
        mem2cacheram    : in     work.libcache.cache_ram_in_type;
        cacheram2mem    : out    work.libcache.cache_ram_out_type;
        iu2cache        : in     work.libcache.dcache_iu_in_type;
        dmmu_invalid    : in     vl_logic;
        dcache2mmu      : out    work.libmmu.mmu_host_cache_out_type;
        dcacheblkcnt    : out    vl_logic;
        dcacherawcnt    : out    vl_logic;
        data_out        : out    vl_logic_vector(63 downto 0);
        dcache2iu       : out    work.libcache.cache2iu_ctrl_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of CACHEDATAPROT : constant is 1;
    attribute mti_svvh_generic_type of AUTORECOVER : constant is 1;
    attribute mti_svvh_generic_type of read2x : constant is 1;
    attribute mti_svvh_generic_type of write2x : constant is 1;
    attribute mti_svvh_generic_type of MMUREFBIT : constant is 1;
    attribute mti_svvh_generic_type of MMUDIRTYBIT : constant is 1;
    attribute mti_svvh_generic_type of NONECCDRAM : constant is 1;
end dcache_udc;
