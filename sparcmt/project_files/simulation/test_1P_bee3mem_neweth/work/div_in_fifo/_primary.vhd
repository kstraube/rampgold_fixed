library verilog;
use verilog.vl_types.all;
library work;
entity div_in_fifo is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libxalu.xalu_in_fifo_type;
        yin             : in     work.libiu.y_reg_type;
        we              : in     vl_logic;
        re              : in     vl_logic;
        dout            : out    work.libxalu.xalu_in_fifo_type;
        yout            : out    work.libiu.y_reg_type;
        valid           : out    vl_logic
    );
end div_in_fifo;
