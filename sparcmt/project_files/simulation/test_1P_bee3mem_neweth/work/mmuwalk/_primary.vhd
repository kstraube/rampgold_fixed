library verilog;
use verilog.vl_types.all;
library work;
entity mmuwalk is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        fromitlb        : in     work.libmmu.mmu_iu_dtlb_type;
        fromdtlb        : in     work.libmmu.mmu_dtlb_mmumem_type;
        toitlb          : out    work.libmmu.mmu_mmumem_itlb_type;
        todtlb          : out    work.libmmu.mmu_mmumem_itlb_type;
        next_level      : in     vl_logic_vector(1 downto 0);
        stop_walk       : in     vl_logic;
        current_level   : out    vl_logic_vector(1 downto 0);
        mmureg_in       : in     work.libmmu.mmureg_write_in_type;
        mmureg_ctx_ptr_dout: out    work.libmmu.mmu_context_table_ptr_register_ram_type;
        fromhc          : in     work.libmmu.mmu_host_cache_out_type;
        tohc            : out    work.libmmu.mmu_host_cache_in_type;
        luterr          : out    vl_logic
    );
end mmuwalk;
