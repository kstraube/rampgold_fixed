library verilog;
use verilog.vl_types.all;
library work;
entity tm_cpu_l1 is
    generic(
        NHOSTGLOBALCNT  : integer := 12
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        cpu2tm          : in     work.libtm.tm_cpu_ctrl_token_type;
        dma2tm          : in     work.libtm.dma_tm_ctrl_type;
        tm2cpu          : out    work.libtm.tm2cpu_token_type;
        io_in           : in     work.libio.io_bus_in_type;
        io_out          : out    work.libio.io_bus_out_type;
        host_global_perf_counter: in     vl_logic_vector;
        tick            : out    vl_logic;
        running         : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of NHOSTGLOBALCNT : constant is 1;
end tm_cpu_l1;
