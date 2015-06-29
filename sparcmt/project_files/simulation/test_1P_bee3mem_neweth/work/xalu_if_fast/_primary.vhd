library verilog;
use verilog.vl_types.all;
library work;
entity xalu_if_fast is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        xalu_in         : in     work.libxalu.xalu_dsp_in_type;
        xalu_out        : out    work.libiu.alu_dsp_out_type;
        new_replay      : out    vl_logic
    );
end xalu_if_fast;
