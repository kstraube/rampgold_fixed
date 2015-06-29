library verilog;
use verilog.vl_types.all;
library work;
entity xalu_div_output_dbuf is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        divin           : in     work.libxalu.xalu_fu_out_type;
        raddr           : in     vl_logic_vector;
        dout            : out    work.libxalu.xalu_obuf_type
    );
end xalu_div_output_dbuf;
