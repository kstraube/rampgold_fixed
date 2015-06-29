library verilog;
use verilog.vl_types.all;
library work;
entity regfile is
    generic(
        protection      : integer := 1;
        nthread         : integer := 64;
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        rfi             : in     work.libiu.regfile_read_in_type;
        rfo             : out    work.libiu.regfile_read_out_type;
        rfc             : in     work.libiu.regfile_commit_type
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of protection : constant is 2;
    attribute mti_svvh_generic_type of nthread : constant is 2;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end regfile;
