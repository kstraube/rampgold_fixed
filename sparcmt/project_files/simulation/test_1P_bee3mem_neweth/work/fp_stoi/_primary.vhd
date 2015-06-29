library verilog;
use verilog.vl_types.all;
entity fp_stoi is
    port(
        clk             : in     vl_logic;
        rst             : in     vl_logic;
        en              : in     vl_logic;
        din             : in     vl_logic_vector(31 downto 0);
        dout            : out    vl_logic_vector(31 downto 0);
        rdy             : out    vl_logic;
        overflow        : out    vl_logic;
        invalid_op      : out    vl_logic
    );
end fp_stoi;
