library verilog;
use verilog.vl_types.all;
library work;
entity fpu_if is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        fpu_in          : in     work.libfp.fpu_in_type;
        fpu_out         : out    work.libfp.fpu_out_type;
        fpop_valid      : out    vl_logic;
        fcmp_valid      : out    vl_logic;
        new_replay      : out    vl_logic
    );
end fpu_if;
