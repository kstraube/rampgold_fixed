//------------------------------------------------------------------------------   
// File:        dumbmmu.sv
// Author:      Zhangxi Tan
// Description: dummy mmu memory map
//------------------------------------------------------------------------------  

parameter USER_HEAP_VIRTUAL_START   = 32'h00000000;
parameter USER_HEAP_PHYSICAL_START  = 32'h00000000;
         
parameter USER_STACK_VIRTUAL_START  = 32'hE0000000;
parameter USER_STACK_PHYSICAL_START = 32'h60000000;
parameter USER_OFFSET_MASK = 32'h0FFFFFFF;

parameter KERNEL_VIRTUAL_START  = 32'hF0000000;
parameter KERNEL_PHYSICAL_START = 32'h70000000;
parameter KERNEL_OFFSET_MASK = 32'h0FFFFFFF;

parameter MMU_COMPARE_MASK = 32'hF0000000;
    
