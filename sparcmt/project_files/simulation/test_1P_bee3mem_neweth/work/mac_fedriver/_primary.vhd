library verilog;
use verilog.vl_types.all;
entity mac_fedriver is
    port(
        rxclk           : in     vl_logic;
        txclk           : in     vl_logic;
        rst             : in     vl_logic;
        rxdv            : out    vl_logic;
        rxd             : out    vl_logic_vector(7 downto 0);
        txd             : in     vl_logic_vector(7 downto 0);
        txen            : in     vl_logic
    );
end mac_fedriver;
