library verilog;
use verilog.vl_types.all;
library work;
entity fpu_fpop_output_dbuf is
    generic(
        DOREG           : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        din             : in     work.libfp.fpu_fpop_fu_out_type;
        raddr           : in     vl_logic_vector;
        dout            : out    work.libfp.fpu_fpop_out_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DOREG : constant is 1;
end fpu_fpop_output_dbuf;
