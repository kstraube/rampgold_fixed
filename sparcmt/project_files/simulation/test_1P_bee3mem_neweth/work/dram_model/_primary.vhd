library verilog;
use verilog.vl_types.all;
library work;
entity dram_model is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        run_reg         : in     vl_logic;
        dram_conf       : in     work.libtm_cache.dram_conf_t;
        tm2cpu          : in     work.libtm.tm2cpu_token_type;
        dma2tm          : in     work.libtm.dma_tm_ctrl_type;
        dram_request    : in     work.libtm_cache.tm_mem_request_t;
        stay_stalled_for_dram: out    vl_logic
    );
end dram_model;
