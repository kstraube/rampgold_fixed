library verilog;
use verilog.vl_types.all;
library work;
entity debug_dma is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        dma_rtid        : in     vl_logic_vector;
        iu2dma          : in     work.libdebug.debug_dma_in_type;
        dma2iu          : out    work.libdebug.debug_dma_out_type;
        dma_rb_in       : out    work.libdebug.debug_dma_read_buffer_in_type;
        dma_rb_out      : in     work.libdebug.debug_dma_read_buffer_out_type;
        dma_wb_in       : out    work.libdebug.debug_dma_write_buffer_in_type;
        dma_cmd_in      : in     work.libdebug.debug_dma_cmdif_in_type;
        dma_cmd_ack     : out    vl_logic;
        dma_done        : out    vl_logic;
        luterr          : out    vl_logic
    );
end debug_dma;
