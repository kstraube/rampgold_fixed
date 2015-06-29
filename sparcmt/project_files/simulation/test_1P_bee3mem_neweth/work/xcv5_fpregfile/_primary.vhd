library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_fpregfile is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        rfi             : in     work.libfp.fpregfile_read_in_type;
        rfo             : out    work.libfp.fpregfile_read_out_type;
        rfc             : in     work.libfp.fpregfile_commit_type
    );
end xcv5_fpregfile;
