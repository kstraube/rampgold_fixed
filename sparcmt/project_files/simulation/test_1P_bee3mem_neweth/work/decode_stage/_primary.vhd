library verilog;
use verilog.vl_types.all;
library work;
entity decode_stage is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        der             : in     work.libiu.decode_reg_type;
        icache_de_out   : in     work.libcache.cache2iu_ctrl_type;
        immu2iu         : in     work.libmmu.immu_iu_out_type;
        regr            : out    work.libiu.reg_reg_type;
        luterr          : out    vl_logic;
        bramerr         : out    vl_logic;
        sb_ecc          : out    vl_logic
    );
end decode_stage;
