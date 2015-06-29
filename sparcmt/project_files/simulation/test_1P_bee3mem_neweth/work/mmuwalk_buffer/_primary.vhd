library verilog;
use verilog.vl_types.all;
library work;
entity mmuwalk_buffer is
    generic(
        LUTRAMDDR       : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libmmu.mmu_walk_request_data_type;
        rtid            : in     vl_logic_vector;
        wtid            : in     vl_logic_vector;
        dout            : out    work.libmmu.mmu_walk_request_data_type;
        we              : in     vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of LUTRAMDDR : constant is 2;
end mmuwalk_buffer;
