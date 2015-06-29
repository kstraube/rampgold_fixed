library verilog;
use verilog.vl_types.all;
library work;
entity mmu_control_register is
    generic(
        DOREG           : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        din             : in     work.libmmu.mmu_control_register_ram_type;
        wtid            : in     vl_logic_vector;
        we              : in     vl_logic;
        rtid            : in     vl_logic_vector;
        dout            : out    work.libmmu.mmu_control_register_ram_type;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DOREG : constant is 2;
end mmu_control_register;
