library verilog;
use verilog.vl_types.all;
library work;
entity perfctr is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        read_addr       : in     vl_logic_vector;
        read_data       : out    vl_logic_vector(63 downto 0);
        increment_addr  : in     vl_logic_vector;
        increment_en    : in     vl_logic
    );
end perfctr;
