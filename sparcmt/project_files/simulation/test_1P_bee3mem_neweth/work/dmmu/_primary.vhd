library verilog;
use verilog.vl_types.all;
library work;
entity dmmu is
    generic(
        DUMMYMMU        : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2dmmu         : in     work.libmmu.dmmu_iu_in_type;
        dmmu2iu         : out    work.libmmu.dmmu_iu_out_type;
        iu2dtlb         : out    work.libmmu.tlb_in_type;
        dtlb2iu         : in     work.libmmu.tlb_out_type;
        mem2dtlb        : in     work.libmmu.tlb_in_type;
        dtlb2mem        : out    work.libmmu.tlb_out_type;
        dmmu2cache      : out    work.libcache.dcache_mmu_in_type;
        parity_error    : out    work.libmmu.tlb_error_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DUMMYMMU : constant is 1;
end dmmu;
