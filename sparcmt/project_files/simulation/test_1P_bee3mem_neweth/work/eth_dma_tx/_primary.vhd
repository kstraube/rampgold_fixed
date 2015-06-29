library verilog;
use verilog.vl_types.all;
library work;
entity eth_dma_tx is
    port(
        reset           : in     vl_logic;
        clk             : in     vl_logic;
        tx_ring_in      : in     work.libeth.eth_tx_ring_data_type;
        tx_to_mac       : out    work.libeth.eth_tx_ring_data_type;
        tx_ring_out     : out    work.libeth.eth_tx_ring_data_type
    );
end eth_dma_tx;
