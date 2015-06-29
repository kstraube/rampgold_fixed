onerror {resume}
quietly WaveActivateNextPane {} 0
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/reset
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/clk
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rx_from_mac
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rx_pipe_out
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/tx_ring_in
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/tx_ring_out
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/mac_init
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/v_rx_pipe_out
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/r_rx_pipe_out
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rstate
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/vstate
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rx_word_count_en
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rx_word_count_rst
add wave -noupdate -group eth_rx /sim_top/sim/gen_eth_dma_master/rx_block/rx_word_count
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/reset
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/clk
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/tx_ring_in
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/tx_to_mac
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/tx_ring_out
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/vstate
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/rstate
add wave -noupdate -group eth_tx /sim_top/sim/gen_eth_dma_master/tx_block/v_tx_ring_out
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/reset
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/clk
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/mac_addr
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/mac_init
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/rx_pipe_in
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/rx_pipe_out
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/tx_ring_in
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/tx_ring_out
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/mac_addr_we
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/word_count_en
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/word_count_rst
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/word_count
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/vstate
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/rstate
add wave -noupdate -group eth_mac_addr /sim_top/sim/gen_eth_dma_master/rx_block/mac_addr_ram/v_tx_ring_out
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/reset
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/clkin
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/clk200
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/ring_clk
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_pipe
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_ring
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_TXD
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_TX_EN
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_TX_ER
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_TX_CLK
add wave -noupdate -group gmii -radix hexadecimal /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_RXD
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_RX_DV
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_RX_ER
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_RX_CLK
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/GMII_RESET_B
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/dfs_clkfx
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/dfs_rst_dly
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/ctrlLockx
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/ctrlLock
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/ethTXclock
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/ethRXclock
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TX_EN_FROM_MAC
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TX_ER_FROM_MAC
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TXD_FROM_MAC
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXclockDelay
add wave -noupdate -group gmii -radix hexadecimal /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdataDelay
add wave -noupdate -group gmii -radix hexadecimal /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdataDelayReg
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdvDelay
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXerDelay
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdvDelayReg
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXerDelayReg
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXmacData
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdata
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXdataValid
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXgoodFrame
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/RXbadFrame
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TXdata
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TXdataValid
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/TXack
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rst
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_fifo_we
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_fifo_re
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_fifo_empty
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_fifo_din
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_fifo_dout
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_shf_data
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/rx_byte_count
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_fifo_we
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_fifo_re
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_fifo_empty
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_fifo_din
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_fifo_dout
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_byte_count
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_byte_count_en
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_byte_count_rst
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/txheader_din
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/txheader_we
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/v_tx_state
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/fifo_rst
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/tx_first_byte
add wave -noupdate -group gmii /sim_top/sim/gen_eth_dma_master/gigaeth/genblk1/macgmii/r_tx_state
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/clk
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/reset
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/rx_pipe_in
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/rx_pipe_out
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/tx_ring_in
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/tx_ring_out
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/dma2tm
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/cpurst
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/vstate
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/rstate
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/v_rx_pipe_out
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/v_tx_ring_out
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/isRetry
add wave -noupdate -group eth_tm_control /sim_top/sim/gen_tm_control/dma2tm_we
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/clk
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/reset
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/gclk
add wave -noupdate -group eth_cpu_control -subitemconfig {/sim_top/sim/gen_cpu_control/rx_pipe_in.msg -expand /sim_top/sim/gen_cpu_control/rx_pipe_in.msg.header -expand /sim_top/sim/gen_cpu_control/rx_pipe_in.msg.data {-radix hexadecimal}} -expand /sim_top/sim/gen_cpu_control/rx_pipe_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/rx_pipe_out
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/tx_ring_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/tx_ring_out
add wave -noupdate -group eth_cpu_control -expand /sim_top/sim/gen_cpu_control/dma_cmd_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/dma_done
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/dma_rb_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/dma_rb_out
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/dma_wb_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/sberr
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/dberr
add wave -noupdate -group eth_cpu_control -expand /sim_top/sim/gen_cpu_control/vstate
add wave -noupdate -group eth_cpu_control -expand /sim_top/sim/gen_cpu_control/rstate
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/v_rx_pipe_out
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/v_tx_ring_out
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/isRetry
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/next_addr
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/next_count
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_din
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_dout
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_we
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_re
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_empty
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/cmd_fifo_rst
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/eth_rb_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/eth_wb_in
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/eth_wb_out
add wave -noupdate -group eth_cpu_control /sim_top/sim/gen_cpu_control/le_data
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/gclk
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/rst
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_rtid
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/iu2dma
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma2iu
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_rb_in
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_rb_out
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_wb_in
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_cmd_in
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_cmd_ack
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/dma_done
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/luterr
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/v_new_addr_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/r_new_addr_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/v_new_ctrl_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/r_new_ctrl_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/addr_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/n_addr_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/ctrl_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/n_ctrl_reg
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/fromiu
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/iu_wtid
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/iu_we
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/addr_reg_error
add wave -noupdate -expand -group dma /sim_top/sim/gen_cpu/gen_iu_dma/ctrl_reg_error
add wave -noupdate /sim_top/sim/gen_cpu/gen_mem/xcr_r
add wave -noupdate /sim_top/sim/gen_cpu/gen_ex/memr
TreeUpdate [SetDefaultTree]
WaveRestoreCursors {{Cursor 1} {258635421 ps} 0}
configure wave -namecolwidth 533
configure wave -valuecolwidth 100
configure wave -justifyvalue left
configure wave -signalnamewidth 0
configure wave -snapdistance 10
configure wave -datasetprefix 0
configure wave -rowmargin 4
configure wave -childrowmargin 2
configure wave -gridoffset 0
configure wave -gridperiod 1
configure wave -griddelta 40
configure wave -timeline 0
configure wave -timelineunits ps
update
WaveRestoreZoom {258082483 ps} {259133747 ps}
