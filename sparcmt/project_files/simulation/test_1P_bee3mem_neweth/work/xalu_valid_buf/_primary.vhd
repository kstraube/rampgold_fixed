library verilog;
use verilog.vl_types.all;
library work;
entity xalu_valid_buf is
    generic(
        DOREG           : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu_vin          : in     work.libxalu.xalu_valid_in_type;
        xalu_vin        : in     work.libxalu.xalu_valid_in_type;
        vout            : out    work.libxalu.xalu_valid_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DOREG : constant is 1;
end xalu_valid_buf;
