library verilog;
use verilog.vl_types.all;
entity fp_cmp_dp is
    port(
        sclr            : in     vl_logic;
        rdy             : out    vl_logic;
        invalid_op      : out    vl_logic;
        operation_nd    : in     vl_logic;
        clk             : in     vl_logic;
        a               : in     vl_logic_vector(63 downto 0);
        b               : in     vl_logic_vector(63 downto 0);
        result          : out    vl_logic_vector(3 downto 0)
    );
end fp_cmp_dp;
