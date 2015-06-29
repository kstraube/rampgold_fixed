library verilog;
use verilog.vl_types.all;
library work;
entity dmmutlb is
    generic(
        LARGEPAGETLB    : vl_logic := Hi1;
        LUTRAMDDR       : vl_logic := Hi0;
        DTLBDOREG       : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2tlb          : in     work.libmmu.mmu_iu_dtlb_type;
        mem2tlb         : in     work.libmmu.mmu_mmumem_itlb_type;
        tlbflush        : in     work.libmmu.mmu_tlb_flush_probe_type;
        valid           : in     vl_logic;
        dirty           : in     vl_logic;
        tlb2iu          : out    work.libmmu.mmu_dtlb_iu_type;
        replay          : out    vl_logic;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of LARGEPAGETLB : constant is 2;
    attribute mti_svvh_generic_type of LUTRAMDDR : constant is 2;
    attribute mti_svvh_generic_type of DTLBDOREG : constant is 1;
end dmmutlb;
