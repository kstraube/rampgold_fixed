library verilog;
use verilog.vl_types.all;
library work;
entity dtlbram_2way_split is
    generic(
        LUTRAMDDR       : integer := 1;
        DTLBDOREG       : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2tlb          : in     work.libmmu.mmu_iu_dtlb_type;
        dirty           : in     vl_logic;
        valid           : in     vl_logic;
        tlbflush        : in     work.libmmu.mmu_tlb_flush_probe_type;
        mem2tlb         : in     work.libmmu.mmu_mmumem_itlb_type;
        tlbram2iu       : out    work.libmmu.mmu_dtlb_iu_type;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of LUTRAMDDR : constant is 2;
    attribute mti_svvh_generic_type of DTLBDOREG : constant is 1;
end dtlbram_2way_split;
