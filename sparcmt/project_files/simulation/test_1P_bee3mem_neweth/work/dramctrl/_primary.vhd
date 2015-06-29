library verilog;
use verilog.vl_types.all;
library work;
entity dramctrl is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        imem_in         : in     vl_logic;
        dmem_in         : in     vl_logic;
        imem_out        : out    vl_logic;
        dmem_out        : out    vl_logic;
        luterr          : out    vl_logic
    );
end dramctrl;
