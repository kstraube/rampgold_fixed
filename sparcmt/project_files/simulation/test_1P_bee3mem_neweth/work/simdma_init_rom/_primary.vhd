library verilog;
use verilog.vl_types.all;
library work;
entity simdma_init_rom is
    generic(
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        raddr           : in     vl_logic_vector(15 downto 0);
        dout            : out    vl_logic_vector(31 downto 0)
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end simdma_init_rom;
