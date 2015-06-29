library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_regfile is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        rfi             : in     work.libiu.regfile_read_in_type;
        rfo             : out    work.libiu.regfile_read_out_type;
        rfc             : in     work.libiu.regfile_commit_type
    );
end xcv5_regfile;
