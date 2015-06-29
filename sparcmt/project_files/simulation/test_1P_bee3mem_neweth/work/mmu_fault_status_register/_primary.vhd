library verilog;
use verilog.vl_types.all;
library work;
entity mmu_fault_status_register is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        din             : in     work.libmmu.mmu_fault_status_register_ram_type;
        we              : in     vl_logic;
        rtid            : in     vl_logic_vector;
        wtid            : in     vl_logic_vector;
        dout            : out    work.libmmu.mmu_fault_status_register_ram_type;
        luterr          : out    vl_logic
    );
end mmu_fault_status_register;
