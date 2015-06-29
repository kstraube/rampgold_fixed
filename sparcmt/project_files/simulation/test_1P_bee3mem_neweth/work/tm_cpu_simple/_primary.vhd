library verilog;
use verilog.vl_types.all;
library work;
entity tm_cpu_simple is
    generic(
        L1_MAX_TAGS     : integer := 16384;
        L1_MAX_ASSOC    : integer := 16;
        L1_MIN_OFFSET_BITS: integer := 4;
        L1_MAX_OFFSET_BITS: integer := 7;
        L1_MAX_MISS_PENALTY: integer := 255;
        L1_INDEX_MSB    : vl_notype;
        L1_TAG_RAM_INDEX_MSB: vl_notype;
        L1_ASSOC_MSB    : vl_notype;
        L1_OFFSET_LSB   : vl_notype;
        L1_OFFSET_BITS_MSB: vl_notype;
        L1_MISS_PENALTY_MSB: vl_notype;
        L1_BANK_SHIFT_MSB: vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        cpu2tm          : in     work.libtm.tm_cpu_ctrl_token_type;
        dma2tm          : in     work.libtm.dma_tm_ctrl_type;
        tm2cpu          : out    work.libtm.tm2cpu_token_type;
        io_in           : in     work.libio.io_bus_in_type;
        io_out          : out    work.libio.io_bus_out_type;
        running         : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of L1_MAX_TAGS : constant is 1;
    attribute mti_svvh_generic_type of L1_MAX_ASSOC : constant is 1;
    attribute mti_svvh_generic_type of L1_MIN_OFFSET_BITS : constant is 1;
    attribute mti_svvh_generic_type of L1_MAX_OFFSET_BITS : constant is 1;
    attribute mti_svvh_generic_type of L1_MAX_MISS_PENALTY : constant is 1;
    attribute mti_svvh_generic_type of L1_INDEX_MSB : constant is 3;
    attribute mti_svvh_generic_type of L1_TAG_RAM_INDEX_MSB : constant is 3;
    attribute mti_svvh_generic_type of L1_ASSOC_MSB : constant is 3;
    attribute mti_svvh_generic_type of L1_OFFSET_LSB : constant is 3;
    attribute mti_svvh_generic_type of L1_OFFSET_BITS_MSB : constant is 3;
    attribute mti_svvh_generic_type of L1_MISS_PENALTY_MSB : constant is 3;
    attribute mti_svvh_generic_type of L1_BANK_SHIFT_MSB : constant is 3;
end tm_cpu_simple;
