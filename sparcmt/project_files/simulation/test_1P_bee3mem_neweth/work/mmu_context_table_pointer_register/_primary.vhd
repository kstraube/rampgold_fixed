library verilog;
use verilog.vl_types.all;
library work;
entity mmu_context_table_pointer_register is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        din             : in     work.libmmu.mmu_context_table_ptr_register_ram_type;
        we              : in     vl_logic;
        raddr           : in     vl_logic_vector;
        waddr           : in     vl_logic_vector;
        dout            : out    work.libmmu.mmu_context_table_ptr_register_ram_type;
        luterr          : out    vl_logic
    );
end mmu_context_table_pointer_register;
