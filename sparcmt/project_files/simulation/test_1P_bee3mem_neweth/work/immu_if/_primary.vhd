library verilog;
use verilog.vl_types.all;
library work;
entity immu_if is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        immu_if_in      : in     work.libmmu.immu_iu_in_type;
        immu_de_out     : out    work.libmmu.immu_iu_out_type;
        mem2tlb         : in     work.libmmu.mmu_mmumem_itlb_type;
        icache_de_in    : out    work.libcache.icache_de_in_type;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic;
        luterr          : out    vl_logic
    );
end immu_if;
