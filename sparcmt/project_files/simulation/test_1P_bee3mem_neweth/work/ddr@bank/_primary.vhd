library verilog;
use verilog.vl_types.all;
entity ddrBank is
    port(
        MCLK            : in     vl_logic;
        MCLK90          : in     vl_logic;
        M90Reset        : in     vl_logic;
        WriteData       : in     vl_logic_vector(15 downto 0);
        ReadData        : out    vl_logic_vector(15 downto 0);
        DQ              : inout  vl_logic_vector(7 downto 0);
        DQS             : inout  vl_logic;
        DQS_L           : inout  vl_logic;
        ForceA          : in     vl_logic;
        StartDQCal      : in     vl_logic;
        ReadBurst       : in     vl_logic;
        WriteBurst      : in     vl_logic;
        CalFail         : out    vl_logic
    );
end ddrBank;
