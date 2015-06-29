library verilog;
use verilog.vl_types.all;
library work;
entity debug_dma_buf is
    generic(
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        eth_rx_clk      : in     vl_logic;
        eth_tx_clk      : in     vl_logic;
        rst             : in     vl_logic;
        eth_rb_in       : in     work.libdebug.debug_dma_read_buffer_in_type;
        eth_wb_in       : in     work.libdebug.debug_dma_write_buffer_in_type;
        eth_wb_out      : out    work.libdebug.debug_dma_write_buffer_out_type;
        dma_rb_in       : in     work.libdebug.debug_dma_read_buffer_in_type;
        dma_rb_out      : out    work.libdebug.debug_dma_read_buffer_out_type;
        dma_wb_in       : in     work.libdebug.debug_dma_write_buffer_in_type;
        dberr           : out    vl_logic;
        sberr           : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end debug_dma_buf;
