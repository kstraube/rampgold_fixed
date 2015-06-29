library verilog;
use verilog.vl_types.all;
library work;
entity timer is
    generic(
        NWIDTH          : integer := 24;
        addrmask        : vl_logic_vector(3 downto 0) := (Hi0, Hi0, Hi0, Hi0)
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        bus_in          : in     work.libio.io_bus_in_type;
        tick            : in     vl_logic;
        irq             : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of NWIDTH : constant is 1;
    attribute mti_svvh_generic_type of addrmask : constant is 2;
end timer;
