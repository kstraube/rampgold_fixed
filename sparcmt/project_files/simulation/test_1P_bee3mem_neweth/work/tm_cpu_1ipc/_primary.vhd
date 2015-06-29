library verilog;
use verilog.vl_types.all;
library work;
entity tm_cpu_1ipc is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        cpu2tm          : in     work.libtm.tm_cpu_ctrl_token_type;
        dma2tm          : in     work.libtm.dma_tm_ctrl_type;
        tm2cpu          : out    work.libtm.tm2cpu_token_type;
        tick            : out    vl_logic;
        running         : out    vl_logic
    );
end tm_cpu_1ipc;
