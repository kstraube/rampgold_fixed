library verilog;
use verilog.vl_types.all;
library work;
entity perfctr_host_counter is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        bus_out         : out    work.libio.io_bus_out_type;
        bus_in          : in     work.libio.io_bus_in_type;
        hostcycle       : in     vl_logic;
        icmiss          : in     vl_logic;
        ldmiss          : in     vl_logic;
        stmiss          : in     vl_logic;
        nretired        : in     vl_logic;
        ldst            : in     vl_logic;
        blkcnt          : in     vl_logic;
        rawcnt          : in     vl_logic;
        replay          : in     vl_logic;
        microcode       : in     vl_logic;
        idlecnt         : in     vl_logic;
        replayfpu       : in     vl_logic;
        replaymul       : in     vl_logic
    );
end perfctr_host_counter;
