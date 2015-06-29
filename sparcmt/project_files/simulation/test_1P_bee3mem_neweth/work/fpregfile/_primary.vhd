library verilog;
use verilog.vl_types.all;
library work;
entity fpregfile is
    generic(
        protection      : integer := 1;
        nthread         : integer := 64;
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        rfi             : in     work.libfp.fpregfile_read_in_type;
        rfo             : out    work.libfp.fpregfile_read_out_type;
        rfc             : in     work.libfp.fpregfile_commit_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of protection : constant is 2;
    attribute mti_svvh_generic_type of nthread : constant is 2;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end fpregfile;
