library verilog;
use verilog.vl_types.all;
library work;
entity alu_adder_logic is
    generic(
        fpgatech        : vl_notype
    );
    port(
        gclk            : in     work.libiu.iu_clk_type;
        rst             : in     vl_logic;
        valid           : in     vl_logic;
        alu_data        : in     work.libiu.alu_dsp_in_type;
        alu_res         : out    work.libiu.alu_dsp_out_type;
        raw_alu_res     : out    vl_logic_vector(31 downto 0)
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of fpgatech : constant is 4;
end alu_adder_logic;
