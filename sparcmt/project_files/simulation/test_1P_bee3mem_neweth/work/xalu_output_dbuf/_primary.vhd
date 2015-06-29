library verilog;
use verilog.vl_types.all;
library work;
entity xalu_output_dbuf is
    generic(
        DOREG           : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        mulin           : in     work.libxalu.xalu_fu_out_type;
        divin           : in     work.libxalu.xalu_fu_out_type;
        raddr           : in     vl_logic_vector;
        dout            : out    work.libxalu.xalu_obuf_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DOREG : constant is 1;
end xalu_output_dbuf;
