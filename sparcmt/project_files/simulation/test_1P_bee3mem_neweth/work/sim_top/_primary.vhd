library verilog;
use verilog.vl_types.all;
entity sim_top is
    generic(
        clkperiod       : integer := 5
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of clkperiod : constant is 1;
end sim_top;
