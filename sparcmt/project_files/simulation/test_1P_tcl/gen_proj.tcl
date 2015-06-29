#create a project
project new . test_1P_bram.mpf work ""  reference

#map unisim
vmap unisims /home/xtan/modelsim/xilinx_library/unisims_ver

#add files
project addfolder cpu
project addfolder tech
project addfolder mem
project addfolder stdlib

project addfile /home/xtan/Xilinx92i/verilog/src/glbl.v

project addfile ../../../lib/stdlib/libstd.v systemverilog stdlib
project addfile ../../../lib/cpu/opcodes.v systemverilog cpu
project addfile ../../../lib/libconf.v systemverilog cpu
project addfile ../../../lib/tech/libtech.v systemverilog tech
project addfile ../../../lib/cpu/libucode.v systemverilog cpu
project addfile ../../../lib/cpu/libiu.v systemverilog cpu
project addfile ../../../lib/tech/xilinx/virtex5/clkgen.v systemverilog tech
project addfile ../../../lib/cpu/clkrst_gen.v systemverilog cpu
project addfile ../../../lib/cpu/libmmu.v systemverilog cpu
project addfile ../../../lib/cpu/libcache.v systemverilog cpu
project addfile ../../../lib/cpu/libxalu.v systemverilog cpu
project addfile ../../../lib/mem/libmemif.v systemverilog mem
project addfile ../../../lib/cpu/ifetch.v systemverilog cpu
project addfile ../../../lib/cpu/immu.v systemverilog cpu
project addfile ../../../lib/cpu/icache.v systemverilog cpu
project addfile ../../../lib/tech/xilinx/virtex5/icacheram.v systemverilog tech
project addfile ../../../lib/cpu/microcode.v systemverilog cpu
project addfile ../../../lib/cpu/decode.v systemverilog cpu
project addfile ../../../lib/cpu/regacc.v systemverilog cpu
project addfile ../../../lib/cpu/alu.v systemverilog cpu
project addfile ../../../lib/cpu/dcache.v systemverilog cpu
project addfile ../../../lib/tech/xilinx/virtex5/dcacheram.v systemverilog tech
project addfile ../../../lib/cpu/dmmu.v systemverilog cpu
project addfile ../../../lib/cpu/memory.v systemverilog cpu
project addfile ../../../lib/cpu/exception.v systemverilog cpu
project addfile ../../../lib/cpu/xalu.v systemverilog cpu
project addfile ../../../lib/tech/techmap.v systemverilog tech
project addfile ../../../lib/tech/xilinx/virtex5/regfile.v systemverilog tech
project addfile ../../../lib/tech/xilinx/virtex5/alulogic.v systemverilog tech
project addfile ../../../lib/mem/memif.v systemverilog mem
project addfile ../../../lib/tech/xilinx/virtex5/bram_memory_128.v systemverilog tech
project addfile ../../../lib/mem/blkmemctrl.v systemverilog mem
project addfile ../../../designs/test_1P_bram/top_1P_bram.v systemverilog

#compile files
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/stdlib/libstd.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/opcodes.v
vlog -work work -vopt -sv ../../../lib/libconf.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/libtech.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/libucode.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/libiu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/xilinx/virtex5/clkgen.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/clkrst_gen.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/libmmu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/libcache.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/libxalu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/mem/libmemif.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/ifetch.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/immu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/icache.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/xilinx/virtex5/icacheram.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/microcode.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/decode.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/regacc.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/alu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/dcache.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/xilinx/virtex5/dcacheram.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/dmmu.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/memory.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/techmap.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/exception.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/cpu/xalu.v
vlog -work work -vopt -sv +incdir+../../../lib/tech/xilinx/virtex5 -nocovercells ../../../lib/tech/xilinx/virtex5/regfile.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/xilinx/virtex5/alulogic.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/mem/memif.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/tech/xilinx/virtex5/bram_memory_128.v
vlog -work work -vopt -sv +incdir+../../../lib/cpu -nocovercells ../../../lib/mem/blkmemctrl.v
vlog -work work -vopt -sv +incdir+../../../designs/test_1P_bram -nocovercells ../../../designs/test_1P_bram/top_1P_bram.v

vlog -work work -vopt -nocovercells /home/xtan/Xilinx92i/verilog/src/glbl.v

#simulation
transcript on
vsim -novopt -L unisims work.sim_top work.glbl

