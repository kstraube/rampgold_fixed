library verilog;
use verilog.vl_types.all;
entity reset_synchronizer is
    port(
        rstin           : in     vl_logic;
        clk             : in     vl_logic;
        rst_s           : out    vl_logic
    );
end reset_synchronizer;
