library verilog;
use verilog.vl_types.all;
library work;
entity immutlb_fast is
    generic(
        LARGEPAGETLB    : vl_logic := Hi1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2tlb          : in     work.libmmu.mmu_iu_itlb_type;
        mem2tlb         : in     work.libmmu.mmu_mmumem_itlb_type;
        tlb2iu          : out    work.libmmu.mmu_itlb_iu_type;
        tlbmiss         : out    vl_logic;
        immu_ctrl_reg   : out    work.libmmu.mmu_control_register_ram_type;
        immu_ctx_reg    : out    work.libmmu.mmu_context_register_type;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of LARGEPAGETLB : constant is 2;
end immutlb_fast;
