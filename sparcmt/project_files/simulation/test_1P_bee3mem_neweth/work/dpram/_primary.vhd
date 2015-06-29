library verilog;
use verilog.vl_types.all;
entity dpram is
    port(
        CLK             : in     vl_logic;
        \in\            : in     vl_logic;
        \out\           : out    vl_logic;
        ra              : in     vl_logic_vector(4 downto 0);
        wa              : in     vl_logic_vector(4 downto 0);
        we              : in     vl_logic
    );
end dpram;
