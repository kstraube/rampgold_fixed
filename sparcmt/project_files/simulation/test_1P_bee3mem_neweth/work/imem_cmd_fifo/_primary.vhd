library verilog;
use verilog.vl_types.all;
library work;
entity imem_cmd_fifo is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        we              : in     vl_logic;
        re              : in     vl_logic;
        din             : in     work.libmemif.imem_cmd_fifo_type;
        dout            : out    work.libmemif.imem_cmd_fifo_type;
        empty           : out    vl_logic;
        bram_addr       : out    work.libcache.cache_ram_read_in_type
    );
end imem_cmd_fifo;
