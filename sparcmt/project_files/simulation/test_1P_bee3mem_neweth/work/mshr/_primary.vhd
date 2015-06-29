library verilog;
use verilog.vl_types.all;
library work;
entity mshr is
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        we              : in     vl_logic;
        waddr           : in     vl_logic_vector(5 downto 0);
        raddr           : in     vl_logic_vector(5 downto 0);
        din             : in     work.udcache_nb_mmu_sv_unit.mshr_entry_type;
        dout            : out    work.udcache_nb_mmu_sv_unit.mshr_entry_type
    );
end mshr;
