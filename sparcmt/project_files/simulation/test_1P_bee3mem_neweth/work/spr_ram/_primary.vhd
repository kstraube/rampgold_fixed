library verilog;
use verilog.vl_types.all;
library work;
entity spr_ram is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        tm2cpu          : in     work.libtm.tm2cpu_token_type;
        wthid           : in     vl_logic_vector;
        spri            : in     work.libiu.spr_commit_type;
        spro            : out    work.libiu.spr_commit_type;
        spre            : in     work.ifetch_dma_sv_unit.spr_parity_type;
        sprd            : out    work.ifetch_dma_sv_unit.spr_parity_type
    );
end spr_ram;
