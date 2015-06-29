library verilog;
use verilog.vl_types.all;
library work;
entity mem_bus_mux is
    generic(
        addr2x          : integer := 0;
        NMEMCTRLPORT    : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        imem_aout       : in     vl_logic;
        dmem_aout       : in     vl_logic;
        imem_dout       : in     vl_logic;
        dmem_dout       : in     vl_logic;
        en              : in     vl_logic;
        port_valid      : in     vl_logic_vector;
        port_mask       : in     vl_logic_vector;
        af_in           : out    work.libmemif.imem_req_addr_buf_type;
        df_in           : out    work.libmemif.imem_req_data_buf_type;
        af_valid        : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of addr2x : constant is 1;
    attribute mti_svvh_generic_type of NMEMCTRLPORT : constant is 2;
end mem_bus_mux;
