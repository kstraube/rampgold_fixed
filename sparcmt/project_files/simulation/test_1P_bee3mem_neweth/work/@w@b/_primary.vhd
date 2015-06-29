library verilog;
use verilog.vl_types.all;
entity WB is
    generic(
        no_ecc_data_path: string  := "FALSE"
    );
    port(
        Reset           : in     vl_logic;
        WD              : in     vl_logic_vector(143 downto 0);
        WRen            : in     vl_logic;
        WRclk           : in     vl_logic;
        Full            : out    vl_logic;
        MD              : out    vl_logic_vector(127 downto 0);
        Rclk            : in     vl_logic;
        RDen            : in     vl_logic;
        Empty           : out    vl_logic
    );
    attribute mti_svvh_generic_type : integer;
    attribute mti_svvh_generic_type of no_ecc_data_path : constant is 1;
end WB;
