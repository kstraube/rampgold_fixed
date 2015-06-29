library verilog;
use verilog.vl_types.all;
entity dpbram18_rfb is
    port(
        wda             : in     vl_logic_vector(35 downto 0);
        aa              : in     vl_logic_vector(8 downto 0);
        wea             : in     vl_logic;
        ena             : in     vl_logic;
        clka            : in     vl_logic;
        rdb             : out    vl_logic_vector(35 downto 0);
        ab              : in     vl_logic_vector(8 downto 0);
        enb             : in     vl_logic;
        clkb            : in     vl_logic
    );
end dpbram18_rfb;
