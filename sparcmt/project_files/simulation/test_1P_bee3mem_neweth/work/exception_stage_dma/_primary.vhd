library verilog;
use verilog.vl_types.all;
library work;
entity exception_stage_dma is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        xcr             : in     work.libiu.xc_reg_type;
        dmmu2iu         : in     work.libmmu.dmmu_iu_out_type;
        dcache2iu       : in     work.libcache.cache2iu_ctrl_type;
        comr            : out    work.libiu.commit_reg_type;
        luterr          : out    vl_logic;
        bramerr         : out    vl_logic;
        sb_ecc          : out    vl_logic;
        irqack          : out    vl_logic;
        errmode         : out    vl_logic;
        iu2dma          : out    work.libdebug.debug_dma_in_type;
        cpu2tm          : out    work.libtm.tm_cpu_ctrl_token_type
    );
end exception_stage_dma;
