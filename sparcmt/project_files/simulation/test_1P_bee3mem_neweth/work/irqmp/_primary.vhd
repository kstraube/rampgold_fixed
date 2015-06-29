library verilog;
use verilog.vl_types.all;
library work;
entity irqmp is
    generic(
        NIRQ            : integer := 2;
        addrmask        : vl_logic_vector(3 downto 0) := (Hi0, Hi0, Hi0, Hi0)
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        bus_in          : in     work.libio.io_bus_in_type;
        irqack          : in     vl_logic;
        bus_out         : out    work.libio.io_bus_out_type;
        irq             : in     vl_logic_vector
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of NIRQ : constant is 1;
    attribute mti_svvh_generic_type of addrmask : constant is 2;
end irqmp;
