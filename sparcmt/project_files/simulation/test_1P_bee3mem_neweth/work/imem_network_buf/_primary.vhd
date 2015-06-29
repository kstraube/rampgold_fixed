library verilog;
use verilog.vl_types.all;
library work;
entity imem_network_buf is
    generic(
        bufdepth        : integer := 32
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        reqin           : in     work.libmemif.mem_ctrl_in_type;
        re              : in     vl_logic;
        aout            : out    work.libmemif.imem_req_addr_buf_type;
        dout            : out    work.libmemif.imem_req_data_buf_type;
        valid           : out    vl_logic;
        nonempty        : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of bufdepth : constant is 1;
end imem_network_buf;
