# Synopsys, Inc. constraint file
# /home/xtan/work/Gold/Hardware/Processor/sparcmt/project_files/synthesis/synplify/top_1P_bee3mem_neweth/top_1P_bee3mem.sdc
# Written on Mon Mar  8 17:22:02 2010
# by Synplify Premier with Design Planner, D-2009.12 Scope Editor

#
# Collections
#
define_scope_collection  TMN_ETHDMAFALSE {find -inst i:gen_eth_dma_master.rr_dma2tm*}
define_scope_collection  TMN_ETHRXFALSE {find -inst i:gen_eth_dma_master.gen_eth_rx_block.r_dma2tm*}
define_scope_collection  TMN_DCACHE_TAG {find -inst i:gen_cpu.gen_dcache.dc_bram.*dc_ram.dc_tag}
define_scope_collection  TMN_DTLBRAM {find -inst i:gen_cpu.gen_dmmu.*.*dtlbram*.*.*.*tlb_ram}
define_scope_collection  TMN_DCACHE_DATA {find -inst i:gen_cpu.gen_dcache.dc_bram.*dc_ram.*dc_data}
define_scope_collection  TMN_DTLBRAM_VPN {find -inst i:gen_cpu.gen_dmmu.*.*.*}
define_scope_collection  TMN_EX_IMMU_DATA {find -inst i:gen_cpu.gen_ex.delr*.*.*}
define_scope_collection  TMN_ITLBRAM {find -inst i:gen_cpu.gen_immu.*.*itlbram*.*.*.*tlb_ram}
define_scope_collection  TMN_ICACHE_TAG {find -inst  i:gen_cpu.gen_icache.ic_bram.*ic_ram.ic_tag}
define_scope_collection  TMN_DCACHE_MSHR {find -inst  i:gen_cpu.gen_dcache.mshr_ram.*}
define_scope_collection  TMN_DCACHE_REG2 {find -inst  i:gen_cpu.gen_dcache.r_we_tag*}
define_scope_collection  TMN_DCACHE_REG1 {find -inst  i:gen_cpu.gen_dcache.delr_xc*}
define_scope_collection  TMN_IRQMP_IPI {find -inst  i:gen_cpu.gen_irqmp.ipi*}
define_scope_collection  TMN_TM_PERFCNTER_REG {find i:gen_cpu.gen_tm.*.*.*inc_read_data*}
define_scope_collection  TMN_TM_PERFCNTER_RAM {find  i:gen_cpu.gen_tm.*.*ring_perf_counter*.myram*}
define_scope_collection  TMN_DTLBREG {find -inst i:gen_cpu.gen_dmmu.*.*.delr_mem1*}
define_scope_collection  TMN_IMMUREG {find -inst i:gen_cpu.gen_immu.*.*.*r_walk_stat*}
define_scope_collection  TMN_DECODE {find -inst i:gen_cpu.gen_de.*}

#
# Clocks
#
define_clock -disable   {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.clkin_buf} -name {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.clkin_buf}  -clockgroup default_clkgroup_0
define_clock -disable   {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.genblk0\.genblk2\.clk_dfs} -name {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.genblk0\.genblk2\.clk_dfs}  -clockgroup default_clkgroup_1
define_clock -disable   {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.genblk0\.genblk4\.clk_dll} -name {gen_gclk_rst.gen_clk.genblk31\.genblk32\.xcv5_gen_clk.genblk0\.genblk4\.clk_dll}  -clockgroup default_clkgroup_2
define_clock -disable   {gen_dcache.mem_cmd\.cmd\.D_2_sqmuxa} -name {gen_dcache.mem_cmd\.cmd\.D_2_sqmuxa}  -clockgroup default_clkgroup_3
define_clock -disable   {p:clkin_n} -name {p:clkin_n}  -freq 200 -clockgroup clkin_group -rise 2.5 -fall 5
define_clock -disable   {p:clkin_p} -name {p:clkin_p}  -freq 200 -clockgroup clkin_group -rise 0 -fall 2.5
define_clock -disable   {p:clkin_p} -name {p:clkin_p}  -freq 200 -clockgroup default_clkgroup_4
define_clock   {p:clkin_p} -name {p:clkin_p}  -period 9.5 -clockgroup default_clkgroup_5
define_clock -disable   {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.MCLKx} -name {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.MCLKx}  -period 4.16 -clockgroup ddr2_clk -rise 0 -fall 2.08
define_clock -disable   {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.MCLK90x} -name {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.MCLK90x}  -period 4.16 -clockgroup ddr2_clk -rise 1.04 -fall 3.12
define_clock -disable   {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.Ph0x} -name {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.Ph0x}  -period 16.64 -clockgroup ddr2_clk -rise 0 -fall 6.24
define_clock -disable   {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.CLKx} -name {n:gen_gclk_rst.gen_dram_clk.genblk35\.genblk36\.genblk37\.xcv5_gen_dram_clk_bee3.CLKx}  -period 8.32 -clockgroup ddr2_clk -rise 0 -fall 4.16
define_clock -disable   {n:gen_eth_dma_master.tx_client_clk_0_o} -name {n:gen_eth_dma_master.tx_client_clk_0_o}  -period 7.7 -clockgroup default_clkgroup_6
define_clock -disable   {n:gen_eth_dma_master.rx_client_clk_0_o} -name {n:gen_eth_dma_master.rx_client_clk_0_o}  -period 7.7 -clockgroup default_clkgroup_7
define_clock -disable   {n:gen_eth_dma_master.gmii_rx_clk_0_delay} -name {n:gen_eth_dma_master.gmii_rx_clk_0_delay}  -period 7.7 -clockgroup default_clkgroup_8
define_clock -disable   {n:gen_eth_dma_master.tx_phy_clk_0_o} -name {n:gen_eth_dma_master.tx_phy_clk_0_o}  -period 7.7 -clockgroup default_clkgroup_9
define_clock   {n:PHY_RXCLK} -name {n:PHY_RXCLK}  -period 7.7 -clockgroup default_clkgroup_10

#
# Clock to Clock
#

#
# Inputs/Outputs
#
define_input_delay -disable      -default -improve 0.00 -route 0.00
define_output_delay -disable     -default -improve 0.00 -route 0.00
define_input_delay -disable      {clkin_p} -improve 0.00 -route 0.00
define_input_delay -disable      {clkin_n} -improve 0.00 -route 0.00
define_input_delay -disable      {rstin} -improve 0.00 -route 0.00
define_input_delay -disable      {irl[3:0]} -improve 0.00 -route 0.00
define_output_delay -disable     {luterr} -improve 0.00 -route 0.00
define_output_delay -disable     {bramerr} -improve 0.00 -route 0.00
define_output_delay -disable     {sb_ecc} -improve 0.00 -route 0.00

#
# Registers
#

#
# Delay Paths
#
define_false_path -disable  -from {{$TMN_ETHRXFALSE}}  -to {{$TMN_ETHDMAFALSE}} 
define_multicycle_path -disable  -from {{$TMN_DTLBRAM}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DTLBRAM}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_DTLBRAM_VPN}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DTLBRAM_VPN}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_EX_IMMU_DATA}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_EX_IMMU_DATA}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_ITLBRAM}}  -to {{$TMN_ICACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_MSHR}}  -to {{$TMN_IRQMP_IPI}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG}}  -to {{$TMN_IRQMP_IPI}} -end 2
define_multicycle_path -disable  -from {{$TMN_TM_PERFCNTER_REG}}  -to {{$TMN_TM_PERFCNTER_RAM}} -end 2
define_multicycle_path -disable  -from {{$TMN_DTLBREG}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DTLBREG}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_MSHR}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_MSHR}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG1}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG1}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG2}}  -to {{$TMN_DCACHE_TAG}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG2}}  -to {{$TMN_DCACHE_DATA}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG1}}  -to {{$TMN_IRQMP_IPI}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_REG2}}  -to {{$TMN_IRQMP_IPI}} -end 2
define_multicycle_path -disable  -from {{$TMN_DCACHE_MSHR}}  -to {{$TMN_IRQMP_IPI}} -end 2
define_multicycle_path -disable  -from {{$TMN_IMMUREG}}  -to {{$TMN_DECODE}} -start 2

#
# Attributes
#
define_global_attribute -disable  {syn_srlstyle} {registers}
define_attribute {i:gen_bee3mem.ddr.WriteBurst} {syn_srlstyle} {select_srl}
define_attribute {i:gen_bee3mem.ddr.ReadBurst} {syn_srlstyle} {select_srl}
define_attribute {i:gen_bee3mem.ddr.odtd3} {syn_srlstyle} {select_srl}
define_attribute -disable {i:gen_ex.xalu_mul_div.mul_ififo.pt\.head[5:0]} {syn_maxfan} {4}
define_attribute -disable {i:gen_ex.xalu_mul_div.mul_ififo.pt\.tail[5:0]} {syn_maxfan} {4}
define_attribute -disable {n:gen_ex.xalu_mul_div.mul_ififo_re} {syn_maxfan} {4}
define_attribute -disable {n:gen_ex.xalu_mul_div.gen_mul_shf.genblk43\.genblk44\.mul_shf.un15} {syn_maxfan} {8}
define_attribute -disable {n:gen_cpu.gen_dcache.dc_bram.genblk57\.genblk58\.dc_ram.t_raddr[8:0]} {syn_maxfan} {4}
define_attribute -disable {i:gen_cpu.gen_dmmu.genblk140\.genblk141\.gen_dmmutlb.genblk137\.genblk138\.dtlbram_split} {syn_maxfan} {8}
define_attribute -disable {i:gen_ex.xalu_mul_div.mul_ififo.pt\.head[5:0]} {syn_allow_retiming} {1}
define_attribute -disable {gen_gclk_rst.reset_dly} {syn_preserve} {1}
define_attribute -disable {gen_gclk_rst.ce} {syn_preserve} {1}
define_attribute {rstin} {xc_loc} {E9}
define_attribute {clkin_p} {xc_loc} {AH15}
define_attribute {done_led} {xc_loc} {H18}
define_attribute {error_led} {xc_loc} {L18}
define_attribute {cpurst} {xc_loc} {AJ6}
define_attribute {TxD} {xc_loc} {AG20}
define_attribute {RxD} {xc_loc} {AG15}
define_attribute {ddr2_we_n} {xc_loc} {K29}
define_attribute {ddr2_cs_n[0]} {xc_loc} {L29}
define_attribute {ddr2_cs_n[1]} {xc_loc} {J29}
define_attribute {ddr2_cke[0]} {xc_loc} {T28}
define_attribute {ddr2_cke[1]} {xc_loc} {U30}
define_attribute {ddr2_ck[0]} {xc_loc} {AK29}
define_attribute {ddr2_ck_n[0]} {xc_loc} {AJ29}
define_attribute {ddr2_ck[1]} {xc_loc} {E28}
define_attribute {ddr2_ck_n[1]} {xc_loc} {F28}
define_attribute {ddr2_a[0]} {xc_loc} {L30}
define_attribute {ddr2_a[1]} {xc_loc} {M30}
define_attribute {ddr2_a[2]} {xc_loc} {N29}
define_attribute {ddr2_a[3]} {xc_loc} {P29}
define_attribute {ddr2_a[4]} {xc_loc} {K31}
define_attribute {ddr2_a[5]} {xc_loc} {L31}
define_attribute {ddr2_a[6]} {xc_loc} {P31}
define_attribute {ddr2_a[7]} {xc_loc} {P30}
define_attribute {ddr2_a[8]} {xc_loc} {M31}
define_attribute {ddr2_a[9]} {xc_loc} {R28}
define_attribute {ddr2_a[10]} {xc_loc} {J31}
define_attribute {ddr2_a[11]} {xc_loc} {R29}
define_attribute {ddr2_a[12]} {xc_loc} {T31}
define_attribute {ddr2_a[13]} {xc_loc} {H29}
define_attribute {ddr2_ba[0]} {xc_loc} {G31}
define_attribute {ddr2_ba[1]} {xc_loc} {J30}
define_attribute {ddr2_ba[2]} {xc_loc} {R31}
define_attribute {ddr2_ras_n} {xc_loc} {H30}
define_attribute {ddr2_cas_n} {xc_loc} {E31}
define_attribute {ddr2_odt[0]} {xc_loc} {F31}
define_attribute {ddr2_odt[1]} {xc_loc} {F30}
define_attribute {ddr2_dq[0]} {xc_loc} {AF30}
define_attribute {ddr2_dq[1]} {xc_loc} {AK31}
define_attribute {ddr2_dq[2]} {xc_loc} {AF31}
define_attribute {ddr2_dq[3]} {xc_loc} {AD30}
define_attribute {ddr2_dq[4]} {xc_loc} {AJ30}
define_attribute {ddr2_dq[5]} {xc_loc} {AF29}
define_attribute {ddr2_dq[6]} {xc_loc} {AD29}
define_attribute {ddr2_dq[7]} {xc_loc} {AE29}
define_attribute {ddr2_dqs[0]} {xc_loc} {AA29}
define_attribute {ddr2_dqs_n[0]} {xc_loc} {AA30}
define_attribute {ddr2_dm[0]} {xc_loc} {AJ31}
define_attribute {ddr2_dq[8]} {xc_loc} {AH27}
define_attribute {ddr2_dq[9]} {xc_loc} {AF28}
define_attribute {ddr2_dq[10]} {xc_loc} {AH28}
define_attribute {ddr2_dq[11]} {xc_loc} {AA28}
define_attribute {ddr2_dq[12]} {xc_loc} {AG25}
define_attribute {ddr2_dq[13]} {xc_loc} {AJ26}
define_attribute {ddr2_dq[14]} {xc_loc} {AG28}
define_attribute {ddr2_dq[15]} {xc_loc} {AB28}
define_attribute {ddr2_dqs[1]} {xc_loc} {AK28}
define_attribute {ddr2_dqs_n[1]} {xc_loc} {AK27}
define_attribute {ddr2_dm[1]} {xc_loc} {AE28}
define_attribute {ddr2_dq[16]} {xc_loc} {AC28}
define_attribute {ddr2_dq[17]} {xc_loc} {AB25}
define_attribute {ddr2_dq[18]} {xc_loc} {AC27}
define_attribute {ddr2_dq[19]} {xc_loc} {AA26}
define_attribute {ddr2_dq[20]} {xc_loc} {AB26}
define_attribute {ddr2_dq[21]} {xc_loc} {AA24}
define_attribute {ddr2_dq[22]} {xc_loc} {AB27}
define_attribute {ddr2_dq[23]} {xc_loc} {AA25}
define_attribute {ddr2_dqs[2]} {xc_loc} {AK26}
define_attribute {ddr2_dqs_n[2]} {xc_loc} {AJ27}
define_attribute {ddr2_dm[2]} {xc_loc} {Y24}
define_attribute {ddr2_dq[24]} {xc_loc} {AC29}
define_attribute {ddr2_dq[25]} {xc_loc} {AB30}
define_attribute {ddr2_dq[26]} {xc_loc} {W31}
define_attribute {ddr2_dq[27]} {xc_loc} {V30}
define_attribute {ddr2_dq[28]} {xc_loc} {AC30}
define_attribute {ddr2_dq[29]} {xc_loc} {W29}
define_attribute {ddr2_dq[30]} {xc_loc} {V27}
define_attribute {ddr2_dq[31]} {xc_loc} {W27}
define_attribute {ddr2_dqs[3]} {xc_loc} {AB31}
define_attribute {ddr2_dqs_n[3]} {xc_loc} {AA31}
define_attribute {ddr2_dm[3]} {xc_loc} {Y31}
define_attribute {ddr2_dq[32]} {xc_loc} {V29}
define_attribute {ddr2_dq[33]} {xc_loc} {Y27}
define_attribute {ddr2_dq[34]} {xc_loc} {Y26}
define_attribute {ddr2_dq[35]} {xc_loc} {W24}
define_attribute {ddr2_dq[36]} {xc_loc} {V28}
define_attribute {ddr2_dq[37]} {xc_loc} {W25}
define_attribute {ddr2_dq[38]} {xc_loc} {W26}
define_attribute {ddr2_dq[39]} {xc_loc} {V24}
define_attribute {ddr2_dqs[4]} {xc_loc} {Y28}
define_attribute {ddr2_dqs_n[4]} {xc_loc} {Y29}
define_attribute {ddr2_dm[4]} {xc_loc} {V25}
define_attribute {ddr2_dq[40]} {xc_loc} {R24}
define_attribute {ddr2_dq[41]} {xc_loc} {P25}
define_attribute {ddr2_dq[42]} {xc_loc} {N24}
define_attribute {ddr2_dq[43]} {xc_loc} {P26}
define_attribute {ddr2_dq[44]} {xc_loc} {T24}
define_attribute {ddr2_dq[45]} {xc_loc} {N25}
define_attribute {ddr2_dq[46]} {xc_loc} {P27}
define_attribute {ddr2_dq[47]} {xc_loc} {N28}
define_attribute {ddr2_dqs[5]} {xc_loc} {E26}
define_attribute {ddr2_dqs_n[5]} {xc_loc} {E27}
define_attribute {ddr2_dm[5]} {xc_loc} {P24}
define_attribute {ddr2_dq[48]} {xc_loc} {M28}
define_attribute {ddr2_dq[49]} {xc_loc} {L28}
define_attribute {ddr2_dq[50]} {xc_loc} {F25}
define_attribute {ddr2_dq[51]} {xc_loc} {H25}
define_attribute {ddr2_dq[52]} {xc_loc} {K27}
define_attribute {ddr2_dq[53]} {xc_loc} {K28}
define_attribute {ddr2_dq[54]} {xc_loc} {H24}
define_attribute {ddr2_dq[55]} {xc_loc} {G26}
define_attribute {ddr2_dqs[6]} {xc_loc} {H28}
define_attribute {ddr2_dqs_n[6]} {xc_loc} {G28}
define_attribute {ddr2_dm[6]} {xc_loc} {F26}
define_attribute {ddr2_dq[56]} {xc_loc} {G25}
define_attribute {ddr2_dq[57]} {xc_loc} {M26}
define_attribute {ddr2_dq[58]} {xc_loc} {J24}
define_attribute {ddr2_dq[59]} {xc_loc} {L26}
define_attribute {ddr2_dq[60]} {xc_loc} {J27}
define_attribute {ddr2_dq[61]} {xc_loc} {M25}
define_attribute {ddr2_dq[62]} {xc_loc} {L25}
define_attribute {ddr2_dq[63]} {xc_loc} {L24}
define_attribute {ddr2_dqs[7]} {xc_loc} {G27}
define_attribute {ddr2_dqs_n[7]} {xc_loc} {H27}
define_attribute {ddr2_dm[7]} {xc_loc} {J25}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.RXD_TO_MAC[7:0]} {syn_useioff} {1}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.RX_DV_TO_MAC} {syn_useioff} {1}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.RX_ER_TO_MAC} {syn_useioff} {1}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.GMII_TXD[7:0]} {syn_useioff} {1}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.GMII_TX_EN} {syn_useioff} {1}
define_attribute {i:gen_eth_dma_master.EMac0_block.gmii0.GMII_TX_ER} {syn_useioff} {1}
define_attribute {PHY_RXD[0]} {xc_loc} {A33}
define_attribute {PHY_RXD[1]} {xc_loc} {B33}
define_attribute {PHY_RXD[2]} {xc_loc} {C33}
define_attribute {PHY_RXD[3]} {xc_loc} {C32}
define_attribute {PHY_RXD[4]} {xc_loc} {D32}
define_attribute {PHY_RXD[5]} {xc_loc} {C34}
define_attribute {PHY_RXD[6]} {xc_loc} {D34}
define_attribute {PHY_RXD[7]} {xc_loc} {F33}
define_attribute {PHY_RXDV} {xc_loc} {E32}
define_attribute {PHY_RXER} {xc_loc} {E33}
define_attribute {PHY_RXCLK} {xc_loc} {H17}
define_attribute {PHY_TXD[0]} {xc_loc} {AF11}
define_attribute {PHY_TXD[1]} {xc_loc} {AE11}
define_attribute {PHY_TXD[2]} {xc_loc} {AH9}
define_attribute {PHY_TXD[3]} {xc_loc} {AH10}
define_attribute {PHY_TXD[4]} {xc_loc} {AG8}
define_attribute {PHY_TXD[5]} {xc_loc} {AH8}
define_attribute {PHY_TXD[6]} {xc_loc} {AG10}
define_attribute {PHY_TXD[7]} {xc_loc} {AG11}
define_attribute {PHY_TXEN} {xc_loc} {AJ10}
define_attribute {PHY_TXER} {xc_loc} {AJ9}
define_attribute {PHY_GTXCLK} {xc_loc} {J16}
define_attribute -disable {PHY_TXCLK} {xc_loc} {K17}
define_attribute -disable {PHY_COL} {xc_loc} {B32}
define_attribute -disable {PHY_CRS} {xc_loc} {E34}
define_attribute {PHY_RESET} {xc_loc} {J14}
define_attribute {error1_led} {xc_loc} {F6}
define_attribute {error2_led} {xc_loc} {T10}
define_attribute {clk200_p} {xc_loc} {L19}
define_attribute {clk200_n} {xc_loc} {K19}
define_attribute -disable {mac_lsn[0]} {xc_loc} {AC24}
define_attribute -disable {mac_lsn[1]} {xc_loc} {AC25}
define_attribute -disable {mac_lsn[2]} {xc_loc} {AE26}
define_attribute -disable {mac_lsn[3]} {xc_loc} {AE27}
define_attribute -disable {i:gen_cpu.gen_dmmu.genblk140\.genblk141\.gen_dmmutlb.genblk137\.genblk138\.dtlbram_split.lru_ram_1} {syn_ramstyle} {select_ram}
define_attribute -disable {i:gen_cpu.gen_dmmu.genblk140\.genblk141\.gen_dmmutlb.genblk137\.genblk138\.dtlbram_split.lru_ram} {syn_ramstyle} {select_ram}
define_attribute -disable {i:gen_cpu.gen_immu.genblk127\.genblk128\.gen_immutlb.genblk121\.genblk122\.itlbram_split.lru_ram} {syn_ramstyle} {select_ram}
define_attribute -disable {i:gen_cpu.gen_immu.genblk127\.genblk128\.gen_immutlb.genblk121\.genblk122\.itlbram_split.lru_ram_1} {syn_ramstyle} {select_ram}
define_global_attribute  {syn_useioff} {1}
define_global_attribute  {syn_ramstyle} {select_ram}

#
# I/O Standards
#
define_io_standard -disable      -default_input -delay_type input
define_io_standard -disable      -default_output -delay_type output
define_io_standard -disable      -default_bidir -delay_type bidir
define_io_standard               {clkin_p} -delay_type input syn_pad_type {LVCMOS_33}
define_io_standard               {clk200_n} -delay_type input syn_pad_type {LVDS_25}
define_io_standard               {clk200_p} -delay_type input syn_pad_type {LVDS_25}
define_io_standard -disable      {clkin_n} -delay_type input
define_io_standard               {rstin} -delay_type input syn_pad_type {LVCMOS_33}
define_io_standard -disable      {irl[3:0]} -delay_type input
define_io_standard -disable      {luterr} -delay_type output
define_io_standard -disable      {bramerr} -delay_type output
define_io_standard -disable      {sb_ecc} -delay_type output
define_io_standard -disable      {done_led} syn_pad_type {LVCMOS_25}
define_io_standard -disable      {error_led} syn_pad_type {LVCMOS_25}
define_io_standard               {cpurst} syn_pad_type {LVCMOS_33}
define_io_standard               {TxD} syn_pad_type {LVCMOS33}
define_io_standard               {RxD} syn_pad_type {LVCMOS33}
define_io_standard               {ddr2_we_n} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_dq[63:0]} syn_pad_type {SSTL18_II_DCI}
define_io_standard               {ddr2_dm[7:0]} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_dqs[7:0]} syn_pad_type {DIFF_SSTL18_II_DCI}
define_io_standard               {ddr2_dqs_n[7:0]} syn_pad_type {DIFF_SSTL18_II_DCI}
define_io_standard               {ddr2_ck[1:0]} syn_pad_type {DIFF_SSTL18_II}
define_io_standard               {ddr2_ck_n[1:0]} syn_pad_type {DIFF_SSTL18_II}
define_io_standard               {ddr2_a[13:0]} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_ras_n} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_cas_n} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_ba[2:0]} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_odt[1:0]} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_cs_n[1:0]} syn_pad_type {SSTL18_II}
define_io_standard               {ddr2_cke[1:0]} syn_pad_type {SSTL18_II}
define_io_standard               {PHY_TXD[7:0]} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_TXEN} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_TXER} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_RXD[7:0]} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_RXDV} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_RXER} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_GTXCLK} syn_pad_type {LVCMOS25}
define_io_standard               {PHY_RXCLK} syn_pad_type {LVCMOS25}
define_io_standard -disable      {PHY_TXCLK} syn_pad_type {LVCMOS25}
define_io_standard -disable      {PHY_COL} syn_pad_type {LVCMOS33}
define_io_standard -disable      {PHY_CRS} syn_pad_type {LVCMOS33}
define_io_standard               {PHY_RESET} syn_pad_type {LVCMOS25}
define_io_standard               {error1_led} syn_pad_type {LVCMOS_33}
define_io_standard               {error2_led} syn_pad_type {LVCMOS_33}
define_io_standard -disable      {mac_lsn[3:0]} syn_pad_type {LVCMOS_18}

#
# Compile Points
#

#
# Other
#
