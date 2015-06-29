library verilog;
use verilog.vl_types.all;
library work;
entity mem_system is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        run_reg         : in     vl_logic;
        l2_conf         : in     work.libtm_cache.l2_conf_t;
        dram_conf       : in     work.libtm_cache.dram_conf_t;
        tm2cpu          : in     work.libtm.tm2cpu_token_type;
        dma2tm          : in     work.libtm.dma_tm_ctrl_type;
        req             : in     work.libtm_cache.tm_mem_request_t;
        stay_stalled    : out    vl_logic;
        l2_ctrs         : out    work.libtm_cache.l2_counters_t
    );
end mem_system;
