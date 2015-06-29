library verilog;
use verilog.vl_types.all;
entity TC5 is
    port(
        Ph0             : in     vl_logic;
        ResetIn         : in     vl_logic;
        TxD             : out    vl_logic;
        RxD             : in     vl_logic;
        StartDQCal0     : out    vl_logic;
        LastALU         : out    vl_logic_vector(35 downto 0);
        injectTC5address: out    vl_logic;
        CalFailed       : in     vl_logic;
        InhibitDDR      : out    vl_logic;
        DDRcke          : out    vl_logic;
        ResetDDR        : out    vl_logic;
        Force           : out    vl_logic;
        HoldFail        : in     vl_logic;
        Start           : out    vl_logic;
        testConf        : out    vl_logic_vector(1 downto 0);
        TakeXD          : out    vl_logic;
        XDbyte          : in     vl_logic_vector(7 downto 0);
        SDA             : out    vl_logic;
        SCL             : out    vl_logic;
        SDAin           : in     vl_logic;
        \Select\        : out    vl_logic;
        Which           : in     vl_logic
    );
end TC5;
