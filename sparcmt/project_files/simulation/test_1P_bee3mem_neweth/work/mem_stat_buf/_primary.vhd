library verilog;
use verilog.vl_types.all;
library work;
entity mem_stat_buf is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        statin          : in     work.libmemif.mem_stat_buf_in_type;
        statout         : out    work.libmemif.mem_stat_out_type
    );
end mem_stat_buf;
