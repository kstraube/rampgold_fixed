library verilog;
use verilog.vl_types.all;
entity RB is
    port(
        Reset           : in     vl_logic;
        MD              : in     vl_logic_vector(127 downto 0);
        WRen            : in     vl_logic;
        WRclk           : in     vl_logic;
        Full            : out    vl_logic;
        RD              : out    vl_logic_vector(143 downto 0);
        Rclk            : in     vl_logic;
        RDen            : in     vl_logic;
        SingleError     : out    vl_logic;
        DoubleError     : out    vl_logic;
        Empty           : out    vl_logic
    );
end RB;
