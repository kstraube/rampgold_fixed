library verilog;
use verilog.vl_types.all;
library work;
entity microcode_rom is
    port(
        upc             : in     vl_logic_vector(4 downto 0);
        uco             : out    work.libucode.microcode_out_type
    );
end microcode_rom;
