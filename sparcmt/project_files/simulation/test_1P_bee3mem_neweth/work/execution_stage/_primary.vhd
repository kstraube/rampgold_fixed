library verilog;
use verilog.vl_types.all;
library work;
entity execution_stage is
    generic(
        DSPINREG        : integer := 1;
        DOREG           : integer := 1;
        FASTMUL         : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        exr             : in     work.libiu.ex_reg_type;
        memr            : out    work.libiu.mem_reg_type;
        iu2dtlb         : out    work.libmmu.mmu_iu_dtlb_type;
        bramerr         : out    vl_logic;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DSPINREG : constant is 1;
    attribute mti_svvh_generic_type of DOREG : constant is 1;
    attribute mti_svvh_generic_type of FASTMUL : constant is 1;
end execution_stage;
