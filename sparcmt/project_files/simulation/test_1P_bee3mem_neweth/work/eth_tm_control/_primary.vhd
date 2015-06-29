library verilog;
use verilog.vl_types.all;
library work;
entity eth_tm_control is
    port(
        clk             : in     vl_logic;
        reset           : in     vl_logic;
        rx_pipe_in      : in     work.libeth.eth_rx_pipe_data_type;
        rx_pipe_out     : out    work.libeth.eth_rx_pipe_data_type;
        tx_ring_in      : in     work.libeth.eth_tx_ring_data_type;
        tx_ring_out     : out    work.libeth.eth_tx_ring_data_type;
        dma2tm          : out    work.libtm.dma_tm_ctrl_type;
        cpurst          : out    vl_logic
    );
end eth_tm_control;
