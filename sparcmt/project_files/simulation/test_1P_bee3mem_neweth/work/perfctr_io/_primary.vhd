library verilog;
use verilog.vl_types.all;
library work;
entity perfctr_io is
    generic(
        NLOCAL          : vl_logic_vector;
        NGLOBAL         : vl_logic_vector;
        addrmask        : vl_logic_vector(3 downto 0) := (Hi0, Hi0, Hi0, Hi0)
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        bus_out         : out    work.libio.io_bus_out_type;
        bus_in          : in     work.libio.io_bus_in_type;
        bus_sel         : out    vl_logic;
        global_inc      : in     vl_logic_vector;
        local_inc       : in     vl_logic_vector;
        local_tid       : in     vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of NLOCAL : constant is 4;
    attribute mti_svvh_generic_type of NGLOBAL : constant is 4;
    attribute mti_svvh_generic_type of addrmask : constant is 2;
end perfctr_io;
