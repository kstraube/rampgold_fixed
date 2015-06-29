library verilog;
use verilog.vl_types.all;
library work;
entity fetch_stage_dma is
    generic(
        newsch          : vl_logic := Hi0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        comr            : in     work.libiu.commit_reg_type;
        der             : out    work.libiu.decode_reg_type;
        immu_if_in      : out    work.libmmu.immu_iu_in_type;
        icache_if_in    : out    work.libcache.icache_if_in_type;
        icache_if_out   : in     vl_logic_vector(31 downto 0);
        luterr          : out    vl_logic;
        dma_rtid        : out    vl_logic_vector;
        dma2iu          : in     work.libdebug.debug_dma_out_type;
        tm2cpu          : in     work.libtm.tm2cpu_token_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of newsch : constant is 2;
end fetch_stage_dma;
