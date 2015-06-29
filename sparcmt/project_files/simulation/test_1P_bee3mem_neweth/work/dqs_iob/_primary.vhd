library verilog;
use verilog.vl_types.all;
entity dqs_iob is
    port(
        MCLK            : in     vl_logic;
        ODDRD1          : in     vl_logic;
        ODDRD2          : in     vl_logic;
        preDQSenL       : in     vl_logic;
        DQS             : inout  vl_logic;
        DQSL            : inout  vl_logic
    );
end dqs_iob;
