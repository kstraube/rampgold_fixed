library verilog;
use verilog.vl_types.all;
library work;
entity retinfo_buf_sdr is
    generic(
        bufdepth        : integer := 64;
        fullcount       : integer := 58;
        nofullflag      : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libmemif.mem_ret_buf_type;
        we              : in     vl_logic;
        re              : in     vl_logic;
        dout            : out    work.libmemif.mem_ret_buf_type;
        valid           : out    vl_logic;
        almost_full     : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of bufdepth : constant is 1;
    attribute mti_svvh_generic_type of fullcount : constant is 1;
    attribute mti_svvh_generic_type of nofullflag : constant is 1;
end retinfo_buf_sdr;
