library verilog;
use verilog.vl_types.all;
library work;
entity dmmu_if is
    generic(
        DTLBDOREG       : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2dmmu         : in     work.libmmu.dmmu_if_iu_in_type;
        dmmu2iu         : out    work.libmmu.dmmu_iu_out_type;
        toitlb          : out    work.libmmu.mmu_mmumem_itlb_type;
        mmu2hc          : out    work.libmmu.mmu_host_cache_in_type;
        hc2mmu          : in     work.libmmu.mmu_host_cache_out_type;
        mmu2hc_invalid  : out    vl_logic;
        itlb_miss       : out    vl_logic;
        dtlb_miss       : out    vl_logic;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DTLBDOREG : constant is 1;
end dmmu_if;
