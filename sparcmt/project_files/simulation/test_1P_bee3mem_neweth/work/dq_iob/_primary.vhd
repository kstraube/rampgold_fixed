library verilog;
use verilog.vl_types.all;
entity dq_iob is
    port(
        MCLK90          : in     vl_logic;
        ICLK            : in     vl_logic;
        Reset           : in     vl_logic;
        DlyInc          : in     vl_logic;
        DlyReset        : in     vl_logic;
        WbufQ0          : in     vl_logic;
        WbufQ1          : in     vl_logic;
        ReadWB          : in     vl_logic;
        DQ              : inout  vl_logic;
        IserdesQ1       : out    vl_logic;
        IserdesQ2       : out    vl_logic
    );
end dq_iob;
