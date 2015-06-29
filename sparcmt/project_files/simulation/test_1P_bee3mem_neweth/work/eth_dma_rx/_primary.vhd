library verilog;
use verilog.vl_types.all;
library work;
entity eth_dma_rx is
    port(
        reset           : in     vl_logic;
        clk             : in     vl_logic;
        rx_from_mac     : in     work.libeth.eth_rx_pipe_data_type;
        rx_pipe_out     : out    work.libeth.eth_rx_pipe_data_type;
        tx_ring_in      : in     work.libeth.eth_tx_ring_data_type;
        tx_ring_out     : out    work.libeth.eth_tx_ring_data_type
    );
end eth_dma_rx;
