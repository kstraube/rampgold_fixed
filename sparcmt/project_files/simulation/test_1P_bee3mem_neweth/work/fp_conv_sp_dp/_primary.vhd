library verilog;
use verilog.vl_types.all;
entity fp_conv_sp_dp is
    port(
        sclr            : in     vl_logic;
        rdy             : out    vl_logic;
        operation_nd    : in     vl_logic;
        clk             : in     vl_logic;
        a               : in     vl_logic_vector(31 downto 0);
        result          : out    vl_logic_vector(63 downto 0)
    );
end fp_conv_sp_dp;
