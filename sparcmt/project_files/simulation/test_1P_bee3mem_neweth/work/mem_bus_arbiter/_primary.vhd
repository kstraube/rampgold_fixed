library verilog;
use verilog.vl_types.all;
library work;
entity mem_bus_arbiter is
    generic(
        NMEMCTRLPORT    : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        en              : in     vl_logic;
        port_valid      : in     vl_logic_vector;
        port_mask       : out    vl_logic_vector;
        rid             : out    vl_logic_vector
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of NMEMCTRLPORT : constant is 2;
end mem_bus_arbiter;
