library verilog;
use verilog.vl_types.all;
library work;
entity perfctr_output_buf is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        ring_ctrl_in    : in     work.libperfctr.perfctr_ring_ctrl_type;
        ring_data_in    : in     vl_logic_vector(31 downto 0);
        io_tid          : in     vl_logic_vector;
        io_we           : in     vl_logic;
        read_data       : out    work.libperfctr.perfctr_ring_buf_type
    );
end perfctr_output_buf;
