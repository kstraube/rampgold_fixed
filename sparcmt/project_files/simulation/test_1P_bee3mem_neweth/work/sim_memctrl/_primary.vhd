library verilog;
use verilog.vl_types.all;
entity sim_memctrl is
    generic(
        MEMSIZE         : integer := 1048576
    );
    port(
        rst             : in     vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of MEMSIZE : constant is 2;
end sim_memctrl;
