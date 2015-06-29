library verilog;
use verilog.vl_types.all;
library work;
entity xcv5_itlbram is
    generic(
        ECC             : string  := "TRUE";
        ECCSCRUB        : string  := "FALSE"
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        raddr           : in     work.libmmu.mmu_itlbram_addr_type;
        waddr           : in     work.libmmu.mmu_itlbram_addr_type;
        we              : in     vl_logic;
        wdata           : in     work.libmmu.mmu_itlbram_data_type;
        rdata           : out    work.libmmu.mmu_itlbram_data_type;
        sberr           : out    vl_logic;
        dberr           : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of ECC : constant is 1;
    attribute mti_svvh_generic_type of ECCSCRUB : constant is 1;
end xcv5_itlbram;
