library verilog;
use verilog.vl_types.all;
library work;
entity memory_stage is
    generic(
        INREG           : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2dtlb         : in     work.libmmu.mmu_iu_dtlb_type;
        mmu2hc          : in     work.libmmu.mmu_host_cache_in_type;
        memr            : in     work.libiu.mem_reg_type;
        io_in           : in     work.libio.io_bus_out_type;
        io_out          : out    work.libio.io_bus_in_type;
        dcache_data     : in     vl_logic_vector(63 downto 0);
        iu2dcache       : out    work.libcache.dcache_iu_in_type;
        iu2dmmu         : out    work.libmmu.dmmu_if_iu_in_type;
        xcr             : out    work.libiu.xc_reg_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of INREG : constant is 1;
end memory_stage;
