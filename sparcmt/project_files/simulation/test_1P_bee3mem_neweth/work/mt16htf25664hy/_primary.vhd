library verilog;
use verilog.vl_types.all;
entity mt16htf25664hy is
    port(
        dq              : inout  vl_logic_vector(63 downto 0);
        addr            : in     vl_logic_vector(13 downto 0);
        ba              : in     vl_logic_vector(2 downto 0);
        ras_n           : in     vl_logic;
        cas_n           : in     vl_logic;
        we_n            : in     vl_logic;
        cs_n            : in     vl_logic_vector(1 downto 0);
        odt             : in     vl_logic_vector(1 downto 0);
        cke             : in     vl_logic_vector(1 downto 0);
        dm              : in     vl_logic_vector(7 downto 0);
        dqs             : inout  vl_logic_vector(7 downto 0);
        dqs_n           : inout  vl_logic_vector(7 downto 0);
        ck              : in     vl_logic_vector(1 downto 0);
        ck_n            : in     vl_logic_vector(1 downto 0)
    );
end mt16htf25664hy;
