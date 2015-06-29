library verilog;
use verilog.vl_types.all;
library work;
entity regacc_stage_dma is
    generic(
        DSPINREG        : integer := 1
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        regr            : in     work.libiu.reg_reg_type;
        comr            : in     work.libiu.commit_reg_type;
        exr             : out    work.libiu.ex_reg_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of DSPINREG : constant is 1;
end regacc_stage_dma;
