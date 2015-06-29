library verilog;
use verilog.vl_types.all;
entity ddrController is
    generic(
        REFRESHINHIBIT  : vl_logic := Hi1;
        no_ecc_data_path: string  := "FALSE"
    );
    port(
        CLK             : in     vl_logic;
        MCLK            : in     vl_logic;
        MCLK90          : in     vl_logic;
        Address         : in     vl_logic_vector(27 downto 0);
        Read            : in     vl_logic;
        WriteAF         : in     vl_logic;
        AFfull          : out    vl_logic;
        AFclock         : in     vl_logic;
        ReadData        : out    vl_logic_vector(143 downto 0);
        ReadRB          : in     vl_logic;
        RBempty         : out    vl_logic;
        RBfull          : out    vl_logic;
        RBclock         : in     vl_logic;
        SingleError     : out    vl_logic;
        DoubleError     : out    vl_logic;
        WriteData       : in     vl_logic_vector(143 downto 0);
        WriteWB         : in     vl_logic;
        WBfull          : out    vl_logic;
        WBclock         : in     vl_logic;
        DQ              : inout  vl_logic_vector(63 downto 0);
        DQS             : inout  vl_logic_vector(7 downto 0);
        DQS_L           : inout  vl_logic_vector(7 downto 0);
        DIMMCK          : out    vl_logic_vector(1 downto 0);
        DIMMCKL         : out    vl_logic_vector(1 downto 0);
        A               : out    vl_logic_vector(13 downto 0);
        BA              : out    vl_logic_vector(2 downto 0);
        DM              : out    vl_logic_vector(7 downto 0);
        RS              : out    vl_logic_vector(1 downto 0);
        RAS             : out    vl_logic;
        CAS             : out    vl_logic;
        WE              : out    vl_logic;
        ODT             : out    vl_logic_vector(1 downto 0);
        ClkEn           : out    vl_logic_vector(1 downto 0);
        StartDQCal0     : in     vl_logic;
        LastALU         : in     vl_logic_vector(35 downto 0);
        injectTC5address: in     vl_logic;
        InhibitDDR      : in     vl_logic;
        Force           : in     vl_logic;
        ResetDDR        : in     vl_logic;
        Reset           : in     vl_logic;
        CalFailed       : out    vl_logic;
        DDRclockEnable  : in     vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of REFRESHINHIBIT : constant is 2;
    attribute mti_svvh_generic_type of no_ecc_data_path : constant is 1;
end ddrController;
