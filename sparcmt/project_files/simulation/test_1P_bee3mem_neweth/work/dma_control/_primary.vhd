library verilog;
use verilog.vl_types.all;
library work;
entity dma_control is
    port(
        clk             : in     vl_logic;
        reset           : in     vl_logic;
        start_dma_empty : in     vl_logic;
        fifo_empty      : in     vl_logic;
        fifo_data       : in     vl_logic_vector(31 downto 0);
        dma_cmd_ack     : in     vl_logic;
        dma_done        : in     vl_logic;
        fifo_read       : out    vl_logic;
        start_dma_re    : out    vl_logic;
        dma_cmd_in      : out    work.libdebug.debug_dma_cmdif_in_type;
        send_data       : out    vl_logic
    );
end dma_control;
