library verilog;
use verilog.vl_types.all;
library work;
entity perfctr_if is
    generic(
        IOADDR          : vl_logic_vector
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        ring_ctrl_in    : in     work.libperfctr.perfctr_ring_ctrl_type;
        ring_data_in    : in     vl_logic_vector(31 downto 0);
        ring_ctrl_out   : out    work.libperfctr.perfctr_ring_ctrl_type;
        ring_data_out   : out    vl_logic_vector(31 downto 0);
        counter         : in     vl_logic_vector(63 downto 0)
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of IOADDR : constant is 4;
end perfctr_if;
