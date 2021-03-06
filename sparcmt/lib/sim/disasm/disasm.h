/* MTI_DPI */

/*
 * Copyright 2002-2012 Mentor Graphics Corporation.
 *
 * Note:
 *   This file is automatically generated.
 *   Please do not edit this file - you will lose your edits.
 *
 * Settings when this file was generated:
 *   PLATFORM = 'linux_x86_64'
 */
#ifndef INCLUDED_DISASM
#define INCLUDED_DISASM

#ifdef __cplusplus
#define DPI_LINK_DECL  extern "C" 
#else
#define DPI_LINK_DECL 
#endif

#include "svdpi.h"


#ifndef MTI_INCLUDED_TYPEDEF_alu_dsp_in_type
#define MTI_INCLUDED_TYPEDEF_alu_dsp_in_type

typedef struct {
    svBitVecVal op1[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op2[SV_PACKED_DATA_NELEMS(32)];
    svBit carryin;
    struct {
        dsp_ctrl_type dsp_ctrl;
        svBitVecVal genflag[SV_PACKED_DATA_NELEMS(3)];
    } al;
    struct {
        svBitVecVal mode[SV_PACKED_DATA_NELEMS(3)];
        svBit op2zero;
        svBit parity;
    } msd;
}  alu_dsp_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_alu_dsp_out_type
#define MTI_INCLUDED_TYPEDEF_alu_dsp_out_type

typedef struct {
    svBitVecVal result[SV_PACKED_DATA_NELEMS(32)];
    svLogicVecVal y[SV_PACKED_DATA_NELEMS(33)];
    svBit wry;
    svBit parity_error;
    svBitVecVal flag[SV_PACKED_DATA_NELEMS(4)];
    svBit tag_overflow;
    svBit divz;
    svBit valid;
}  alu_dsp_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_regfile_commit_type
#define MTI_INCLUDED_TYPEDEF_regfile_commit_type

typedef struct {
    svBitVecVal ph1_addr;
    svBitVecVal ph2_addr;
    svBitVecVal ph1_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal ph2_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal ph1_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal ph2_parity[SV_PACKED_DATA_NELEMS(7)];
    svBit ph1_we;
    svBit ph2_we;
}  regfile_commit_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpregfile_commit_type
#define MTI_INCLUDED_TYPEDEF_fpregfile_commit_type

typedef struct {
    svBitVecVal ph_addr;
    svBitVecVal ph1_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal ph2_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal ph1_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal ph2_parity[SV_PACKED_DATA_NELEMS(7)];
    svBit ph1_we;
    svBit ph2_we;
}  fpregfile_commit_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_spr_commit_type
#define MTI_INCLUDED_TYPEDEF_spr_commit_type

typedef struct {
    svBitVecVal pc[SV_PACKED_DATA_NELEMS(30)];
    svBitVecVal npc[SV_PACKED_DATA_NELEMS(30)];
    svBit pc_we;
    svBit npc_we;
    svBitVecVal psr[SV_PACKED_DATA_NELEMS(13)];
    svBitVecVal fsr[SV_PACKED_DATA_NELEMS(23)];
    svLogicVecVal y[SV_PACKED_DATA_NELEMS(33)];
    svBitVecVal wim[SV_PACKED_DATA_NELEMS(7)];
    svBit archr_we;
    svBit psr_we;
    svBit run;
    svBit valid;
    svBit icmiss;
    svBit replay;
    svBit annul;
    svBit ucmode;
    svBit dma_mode;
    svBitVecVal upc[SV_PACKED_DATA_NELEMS(5)];
    svBitVecVal flushidx[SV_PACKED_DATA_NELEMS(3)];
    svBit ts_we;
}  spr_commit_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_commit_reg_type
#define MTI_INCLUDED_TYPEDEF_commit_reg_type

typedef struct {
    regfile_commit_type regf;
    fpregfile_commit_type fpregf;
    spr_commit_type spr;
}  commit_reg_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_cmdif_in_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_cmdif_in_type

typedef struct {
    svBitVecVal tid;
    svBitVecVal addr_reg[SV_PACKED_DATA_NELEMS(31)];
    svBit addr_we;
    svBitVecVal ctrl_reg[SV_PACKED_DATA_NELEMS(22)];
    svBit ctrl_we;
}  debug_dma_cmdif_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_in_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_in_type

typedef struct {
    svBitVecVal tid;
    svBit ack;
    svBit done;
    svBitVecVal state[SV_PACKED_DATA_NELEMS(83)];
}  debug_dma_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_out_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_out_type

typedef struct {
    svBitVecVal inst[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal state[SV_PACKED_DATA_NELEMS(83)];
}  debug_dma_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_read_buffer_in_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_read_buffer_in_type

typedef struct {
    svBitVecVal addr[SV_PACKED_DATA_NELEMS(10)];
    svBit we;
    svBitVecVal inst[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal data[SV_PACKED_DATA_NELEMS(32)];
}  debug_dma_read_buffer_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_read_buffer_out_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_read_buffer_out_type

typedef struct {
    svBitVecVal inst[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal data[SV_PACKED_DATA_NELEMS(32)];
}  debug_dma_read_buffer_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_write_buffer_in_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_write_buffer_in_type

typedef struct {
    svBitVecVal addr[SV_PACKED_DATA_NELEMS(10)];
    svBit we;
    svBitVecVal data[SV_PACKED_DATA_NELEMS(32)];
    svBit parity;
}  debug_dma_write_buffer_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_debug_dma_write_buffer_out_type
#define MTI_INCLUDED_TYPEDEF_debug_dma_write_buffer_out_type

typedef struct {
    svBitVecVal data[SV_PACKED_DATA_NELEMS(32)];
    svBit parity;
}  debug_dma_write_buffer_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_thread_state_type
#define MTI_INCLUDED_TYPEDEF_thread_state_type

typedef struct {
    svBitVecVal tid;
    svBit tid_parity;
    svBitVecVal inst[SV_PACKED_DATA_NELEMS(32)];
    svBit run;
    svBit valid;
    svBit replay;
    svBit annul;
    svBit ucmode;
    svBit dma_mode;
    svBit icmiss;
    svBitVecVal psr[SV_PACKED_DATA_NELEMS(13)];
    svBitVecVal fsr[SV_PACKED_DATA_NELEMS(23)];
    svBitVecVal wim[SV_PACKED_DATA_NELEMS(7)];
    svLogicVecVal y[SV_PACKED_DATA_NELEMS(33)];
    svBitVecVal pc[SV_PACKED_DATA_NELEMS(30)];
    svBitVecVal npc[SV_PACKED_DATA_NELEMS(30)];
    svBitVecVal flushidx[SV_PACKED_DATA_NELEMS(3)];
    svBitVecVal upc[SV_PACKED_DATA_NELEMS(5)];
    svBit rdmask;
    svBit uend;
    svBit ldst_a;
    svBitVecVal asi[SV_PACKED_DATA_NELEMS(5)];
    svBitVecVal dma_state[SV_PACKED_DATA_NELEMS(83)];
}  thread_state_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_decode_reg_type
#define MTI_INCLUDED_TYPEDEF_decode_reg_type

typedef struct {
    thread_state_type ts;
    svBitVecVal microinst[SV_PACKED_DATA_NELEMS(32)];
    svBit rs1mask;
    svBit rs2mask;
    svBit cwp_rs1;
    svBit cwp_rd;
}  decode_reg_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_disasm_info_type
#define MTI_INCLUDED_TYPEDEF_disasm_info_type

typedef struct {
    int64_t ctime;
    int tid;
    int inst;
    int pc;
    int replay;
    int annul;
    int dma_mode;
    int uc_mode;
    int upc;
}  disasm_info_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_dsp_ctrl_type
#define MTI_INCLUDED_TYPEDEF_dsp_ctrl_type

typedef struct {
    svLogicVecVal opmode[SV_PACKED_DATA_NELEMS(7)];
    svLogicVecVal alumode[SV_PACKED_DATA_NELEMS(4)];
}  dsp_ctrl_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_error_stat_type
#define MTI_INCLUDED_TYPEDEF_error_stat_type

typedef struct {
    svBit spr_sbit;
    svBit spr_dbit;
    svBit cache_sbit;
    svBit cache_dbit;
    svBit tlb_sbit;
    svBit tlb_dbit;
}  error_stat_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_immu_data_type
#define MTI_INCLUDED_TYPEDEF_immu_data_type

typedef struct {
    svBitVecVal l[SV_PACKED_DATA_NELEMS(2)];
    svBitVecVal at[SV_PACKED_DATA_NELEMS(3)];
    svBit exception;
    svBitVecVal ft[SV_PACKED_DATA_NELEMS(3)];
    svBit tlbmiss;
    struct {
        svBit nf;
        svBit e;
    } ctrl_reg;
    svBitVecVal ctx_reg[SV_PACKED_DATA_NELEMS(4)];
}  immu_data_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_data_type
#define MTI_INCLUDED_TYPEDEF_fpu_data_type

typedef struct {
    svBitVecVal op1[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op2[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op3[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op4[SV_PACKED_DATA_NELEMS(32)];
    svBit op1_parity;
    svBit op2_parity;
    svBit op3_parity;
    svBit op4_parity;
    svBitVecVal fp_op[SV_PACKED_DATA_NELEMS(4)];
    svBit sp_ops;
    svBit sp_result;
}  fpu_data_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_ex_reg_type
#define MTI_INCLUDED_TYPEDEF_ex_reg_type

typedef struct {
    thread_state_type ts;
    svBit annul_next;
    svBit branch_true;
    immu_data_type immu_data;
    alu_dsp_in_type aludata;
    fpu_data_type fpudata;
    svBit op1_parity;
    svBit op2_parity;
    svBit ign_op1_seu;
    svBit ign_op2_seu;
    svBit wicc;
    svBit wy;
    svBitVecVal store_data[SV_PACKED_DATA_NELEMS(32)];
    svBit adder_valid;
    svBit mul_valid;
    svBitVecVal tt[SV_PACKED_DATA_NELEMS(6)];
    svBit trap;
    svBit ticc_trap;
}  ex_reg_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpregfile_read_in_type
#define MTI_INCLUDED_TYPEDEF_fpregfile_read_in_type

typedef struct {
    svBitVecVal op1_addr;
    svBitVecVal op2_addr;
}  fpregfile_read_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpregfile_read_out_type
#define MTI_INCLUDED_TYPEDEF_fpregfile_read_out_type

typedef struct {
    svBitVecVal op1_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op2_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op3_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op4_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op1_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal op2_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal op3_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal op4_parity[SV_PACKED_DATA_NELEMS(7)];
}  fpregfile_read_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_fcmp_out_type
#define MTI_INCLUDED_TYPEDEF_fpu_fcmp_out_type

typedef struct {
    svBitVecVal cc[SV_PACKED_DATA_NELEMS(4)];
    svBit invalid_op;
}  fpu_fcmp_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_fcmp_fu_out_type
#define MTI_INCLUDED_TYPEDEF_fpu_fcmp_fu_out_type

typedef struct {
    fpu_fcmp_out_type data;
    svBitVecVal tid;
    svBit valid;
}  fpu_fcmp_fu_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_fpop_out_type
#define MTI_INCLUDED_TYPEDEF_fpu_fpop_out_type

typedef struct {
    svBitVecVal result[SV_PACKED_DATA_NELEMS(64)];
    svBit overflow;
    svBit underflow;
    svBit invalid_op;
}  fpu_fpop_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_fpop_fu_out_type
#define MTI_INCLUDED_TYPEDEF_fpu_fpop_fu_out_type

typedef struct {
    fpu_fpop_out_type data;
    svBitVecVal tid;
    svBit valid;
}  fpu_fpop_fu_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_in_type
#define MTI_INCLUDED_TYPEDEF_fpu_in_type

typedef struct {
    svBitVecVal tid;
    svBitVecVal op1[SV_PACKED_DATA_NELEMS(64)];
    svBitVecVal op2[SV_PACKED_DATA_NELEMS(64)];
    svBitVecVal fp_op[SV_PACKED_DATA_NELEMS(4)];
    svBit sp_ops;
    svBit sp_result;
    svBit replay;
}  fpu_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_fpu_out_type
#define MTI_INCLUDED_TYPEDEF_fpu_out_type

typedef struct {
    fpu_fpop_out_type fpop_result;
    fpu_fcmp_out_type fcmp_result;
}  fpu_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_iu_clk_type
#define MTI_INCLUDED_TYPEDEF_iu_clk_type

typedef struct {
    svBit clk;
    svBit clk2x;
    svBit ce;
    svBit io_reset;
}  iu_clk_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_mem_reg_type
#define MTI_INCLUDED_TYPEDEF_mem_reg_type

typedef struct {
    thread_state_type ts;
    svBit invalid;
    immu_data_type immu_data;
    svBit annul_next;
    svBit branch_true;
    svBitVecVal ex_res[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal adder_res[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal store_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal tt[SV_PACKED_DATA_NELEMS(6)];
    svBit trap;
    svBit ticc_trap;
    svBit tag_trap;
    svBit divz_trap;
    svBit ieee754_trap;
    svBitVecVal fp_ex_res[SV_PACKED_DATA_NELEMS(64)];
}  mem_reg_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_pre_trap_type
#define MTI_INCLUDED_TYPEDEF_pre_trap_type

typedef struct {
    svBit precise_trap;
    svBit irq_trap;
    svBit nodaex;
    svBitVecVal tbr_tt[SV_PACKED_DATA_NELEMS(8)];
}  pre_trap_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_reg_reg_type
#define MTI_INCLUDED_TYPEDEF_reg_reg_type

typedef struct {
    thread_state_type ts;
    svBit iaex;
    immu_data_type immu_data;
    svBit branch_true;
    svBit wovrf;
    svBit wundf;
    svBit annul_next;
    svBitVecVal rs1;
    svBitVecVal rs2;
    svBitVecVal fprs1;
    svBitVecVal fprs2;
}  reg_reg_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_regfile_read_in_type
#define MTI_INCLUDED_TYPEDEF_regfile_read_in_type

typedef struct {
    svBitVecVal op1_addr;
    svBitVecVal op2_addr;
}  regfile_read_in_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_regfile_read_out_type
#define MTI_INCLUDED_TYPEDEF_regfile_read_out_type

typedef struct {
    svBitVecVal op1_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op2_data[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal op1_parity[SV_PACKED_DATA_NELEMS(7)];
    svBitVecVal op2_parity[SV_PACKED_DATA_NELEMS(7)];
}  regfile_read_out_type;

#endif

#ifndef MTI_INCLUDED_TYPEDEF_xc_reg_type
#define MTI_INCLUDED_TYPEDEF_xc_reg_type

typedef struct {
    thread_state_type ts;
    svBit invalid;
    svBit annul_next;
    svBit branch_true;
    svBitVecVal ex_res[SV_PACKED_DATA_NELEMS(32)];
    svBitVecVal fp_ex_res[SV_PACKED_DATA_NELEMS(64)];
    svBitVecVal io_res[SV_PACKED_DATA_NELEMS(32)];
    svBit io_op;
    svBitVecVal mem_res[SV_PACKED_DATA_NELEMS(64)];
    svBit signext;
    svBitVecVal byte_mask[SV_PACKED_DATA_NELEMS(4)];
    pre_trap_type trap_res;
}  xc_reg_type;

#endif


DPI_LINK_DECL DPI_DLLESPEC
void
init_disasm();

DPI_LINK_DECL DPI_DLLESPEC
void
sparc_disasm(
    const disasm_info_type* dis);

#endif 
