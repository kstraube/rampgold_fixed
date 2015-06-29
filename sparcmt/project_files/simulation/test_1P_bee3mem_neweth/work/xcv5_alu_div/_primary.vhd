library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_alu_div is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libxalu.xalu_in_fifo_type;
        en              : in     vl_logic;
        yin             : in     work.libiu.y_reg_type;
        dout            : out    work.libxalu.xalu_fu_out_type;
        re              : out    vl_logic
    );
end xcv5_alu_div;
