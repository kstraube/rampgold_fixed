library verilog;
use verilog.vl_types.all;
library work;
entity dramctrl_fast is
    generic(
        no_retbuf_fullflag: integer := 0;
        NMEMCTRLPORT    : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        imem_in         : in     vl_logic;
        dmem_in         : in     vl_logic;
        imem_out        : out    vl_logic;
        dmem_out        : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of no_retbuf_fullflag : constant is 1;
    attribute mti_svvh_generic_type of NMEMCTRLPORT : constant is 2;
end dramctrl_fast;
