library verilog;
use verilog.vl_types.all;
library work;
entity itlbram_2way_split is
    generic(
        LUTRAMDDR       : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2tlb          : in     work.libmmu.mmu_iu_itlb_type;
        ctx             : in     vl_logic_vector;
        tlbflush        : in     work.libmmu.mmu_tlb_flush_probe_type;
        mem2tlb         : in     work.libmmu.mmu_mmumem_itlb_type;
        tlbram2iu       : out    work.libmmu.mmu_itlb_iu_type;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of LUTRAMDDR : constant is 2;
end itlbram_2way_split;
