library verilog;
use verilog.vl_types.all;
entity fp_itos is
    port(
        sclr            : in     vl_logic;
        rdy             : out    vl_logic;
        operation_nd    : in     vl_logic;
        clk             : in     vl_logic;
        a               : in     vl_logic_vector(31 downto 0);
        result          : out    vl_logic_vector(31 downto 0)
    );
end fp_itos;
