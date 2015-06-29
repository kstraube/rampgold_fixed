library verilog;
use verilog.vl_types.all;
entity AF is
    port(
        WD              : in     vl_logic_vector(26 downto 0);
        WEn             : in     vl_logic;
        WriteClk        : in     vl_logic;
        Full            : out    vl_logic;
        RD              : out    vl_logic_vector(26 downto 0);
        Empty           : out    vl_logic;
        REn             : in     vl_logic;
        RDClk           : in     vl_logic;
        Reset           : in     vl_logic
    );
end AF;
