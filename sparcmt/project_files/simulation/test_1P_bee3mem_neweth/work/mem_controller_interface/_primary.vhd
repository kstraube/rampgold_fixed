library verilog;
use verilog.vl_types.all;
library work;
entity mem_controller_interface is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic
    );
end mem_controller_interface;
