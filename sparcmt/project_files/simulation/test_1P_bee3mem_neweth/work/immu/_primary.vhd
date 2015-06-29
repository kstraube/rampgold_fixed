library verilog;
use verilog.vl_types.all;
library work;
entity immu is
    generic(
        DUMMYMMU        : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        immu_if_in      : in     work.libmmu.immu_iu_in_type;
        immu_de_out     : out    work.libmmu.immu_iu_out_type;
        iu2itlb         : out    work.libmmu.tlb_in_type;
        itlb2iu         : in     work.libmmu.tlb_out_type;
        mem2itlb        : in     work.libmmu.tlb_in_type;
        itlb2mem        : out    work.libmmu.tlb_out_type;
        icache_de_in    : out    work.libcache.icache_de_in_type;
        parity_error    : out    work.libmmu.tlb_error_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DUMMYMMU : constant is 1;
end immu;
