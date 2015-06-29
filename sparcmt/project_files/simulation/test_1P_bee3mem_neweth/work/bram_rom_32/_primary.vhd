library verilog;
use verilog.vl_types.all;
library work;
entity bram_rom_32 is
    generic(
        ADDRMSB         : integer := 12;
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        addr            : in     vl_logic_vector;
        dout            : out    vl_logic_vector(31 downto 0)
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of ADDRMSB : constant is 2;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end bram_rom_32;
