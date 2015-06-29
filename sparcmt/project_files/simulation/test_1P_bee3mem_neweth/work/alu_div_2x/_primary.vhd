library verilog;
use verilog.vl_types.all;
library work;
entity alu_div_2x is
    generic(
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libxalu.xalu_in_fifo_type;
        en              : in     vl_logic;
        yin             : in     work.libiu.y_reg_type;
        dout            : out    work.libxalu.xalu_fu_out_type;
        re              : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end alu_div_2x;
