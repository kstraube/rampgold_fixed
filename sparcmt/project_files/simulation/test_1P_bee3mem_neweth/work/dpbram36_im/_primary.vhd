library verilog;
use verilog.vl_types.all;
entity dpbram36_im is
    port(
        wda             : in     vl_logic_vector(35 downto 0);
        rda             : out    vl_logic_vector(35 downto 0);
        aa              : in     vl_logic_vector(9 downto 0);
        wea             : in     vl_logic;
        ena             : in     vl_logic;
        clka            : in     vl_logic;
        wdb             : in     vl_logic_vector(35 downto 0);
        rdb             : out    vl_logic_vector(35 downto 0);
        ab              : in     vl_logic_vector(9 downto 0);
        web             : in     vl_logic;
        enb             : in     vl_logic;
        clkb            : in     vl_logic
    );
end dpbram36_im;
