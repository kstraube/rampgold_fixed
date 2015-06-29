library verilog;
use verilog.vl_types.all;
library work;
entity dmem_if is
    generic(
        INITCREDIT      : integer := 2;
        read2x          : integer := 0;
        write2x         : integer := 0;
        nonblocking     : integer := 0
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        iu2mem_tid      : in     vl_logic_vector;
        iu2mem_cmd      : in     work.libmemif.mem_cmd_in_type;
        mem2iu_stat     : out    work.libmemif.mem_stat_out_type;
        cacheram2mem    : in     work.libcache.cache_ram_out_type;
        mem2cacheram    : out    work.libcache.cache_ram_in_type;
        from_mem        : in     work.libmemif.mem_ctrl_out_type;
        to_mem          : out    work.libmemif.mem_ctrl_in_type;
        luterr          : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of INITCREDIT : constant is 1;
    attribute mti_svvh_generic_type of read2x : constant is 1;
    attribute mti_svvh_generic_type of write2x : constant is 1;
    attribute mti_svvh_generic_type of nonblocking : constant is 1;
end dmem_if;
