library verilog;
use verilog.vl_types.all;
entity rs232rcv is
    port(
        Ph0             : in     vl_logic;
        RxD             : in     vl_logic;
        rData           : out    vl_logic_vector(7 downto 0);
        ready           : out    vl_logic;
        readSR          : in     vl_logic
    );
end rs232rcv;
