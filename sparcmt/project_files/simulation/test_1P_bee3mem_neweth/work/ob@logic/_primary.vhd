library verilog;
use verilog.vl_types.all;
entity obLogic is
    port(
        CLK             : in     vl_logic;
        Reset           : in     vl_logic;
        row             : in     vl_logic_vector(13 downto 0);
        bank            : in     vl_logic_vector(2 downto 0);
        rank            : in     vl_logic;
        refRank         : in     vl_logic;
        doOp            : in     vl_logic;
        doReset         : in     vl_logic;
        redoValid       : in     vl_logic;
        numOps          : out    vl_logic_vector(2 downto 0)
    );
end obLogic;
