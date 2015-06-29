library verilog;
use verilog.vl_types.all;
library work;
entity disassembler is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        xcr             : in     work.libiu.xc_reg_type;
        dcache_replay   : in     vl_logic
    );
end disassembler;
