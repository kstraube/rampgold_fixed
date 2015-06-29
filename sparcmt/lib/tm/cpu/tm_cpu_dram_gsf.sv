//------------------------------------------------------------------------------ 
// File:        tm_cpu_dram_gsf.sv
// Author:      Zhangxi Tan
// Description: A DRAM timing model with gsf support, assume a magic interconnect
//              to mem controller
//------------------------------------------------------------------------------  


`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libiu::*;
import libio::*;
import libstd::*;
import libdebug::*;
import libtm::*;
import libopcodes::*;
import libtm_cache::*;
`else
`include "../../cpu/libiu.sv"
`include "../../io/libio.sv"
`include "../libtm.sv"
`include "libtm_cache.sv"
`endif

/*
module dram_gsf_scheduler (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t dram_request,
                   output bit 	stay_stalled_for_dram);
      bit[NTHREADIDMSB+1:0] ntokens,nthreads;

       (* syn_ramstyle = "select_ram" *) bit [NTHREADIDMSB:0]           stay_stalled_for_gsf;
       bit stay_stalled_for_gsf_we, stay_stalled_for_gsf_din;
       
       bit[log2x(MAX_MISS_PENALTY)-1:0]  partition_credits[NPARTITIONIDMSB:0];
       
       bit [NTHREADIDMSB+1:0]            partition_queue_head[0:NPARTITION-1];
       bit [NPARTITION-1:0]              partition_queue_deq, partition_queue_empty;
       
       bit                               has_credit_to_deq;
       
       bit [MAX_MEMCONTROLLER-1:0]       stalled_for_dram;
       
       tm_mem_request_t                  dram_request_gsf[0:MAX_MEMCONTROLLER-1];
       
       bit[log2x(MAX_MISS_PENALTY)-1:0]  gsf_cycle_count;
       
      always_comb begin
        dram_request_gsf = '{default:dram_request};   //default value
        partition_queue_deq = '0;
        
        has_credit_to_deq = (partition_queue_head[dram_request.partitionid] == dram_request.tid) & ((partition_credits[dram_request.partitionid] > 1 && dram_request.writeback_valid)  || (partition_credits[dram_request.partitionid] > 0 && !dram_request.writeback_valid));
        
        partition_queue_deq[dram_request.partitionid] =  has_credit_to_deq & dram_request.token_valid & ~partition_queue_empty[dram_request.partitionid];

        for (int i=0;i<MAX_MEMCONTROLLER;i++) begin
          dram_request_gsf[i].request_valid = dram_request_gsf[i].request_valid & has_credit_to_deq & ((dram_request.request_addr[MEMCONTROLLERLSB +: log2x(MAX_MEMCONTROLLER)] & dram_conf.memcontroller_mask) == i);
          dram_request_gsf[i].writeback_valid = dram_request_gsf[i].writeback_valid & has_credit_to_deq & ((dram_request.writeback_addr[MEMCONTROLLERLSB +: log2x(MAX_MEMCONTROLLER)] & dram_conf.memcontroller_mask) == i);
        end

        stay_stalled_for_dram = |stalled_for_dram | stay_stalled_for_gsf[dram_request.tid];
                
        //stay_stalled_for_gsf
        stay_stalled_for_gsf_we = rst;
        stay_stalled_for_gsf_din = '0;
        
        if (dram_request.token_valid && !rst) begin
          if(dram_request.request_valid) begin      
            stay_stalled_for_gsf_we = '1;
            stay_stalled_for_gsf_din = '1;
          end
          else if (partition_queue_deq[dram_request.partitionid])
            stay_stalled_for_gsf_we = '1;
        end
      end
      
      //ram
      always_ff @(posedge gclk.clk) if (stay_stalled_for_gsf_we) stay_stalled_for_gsf[dram_request.tid] <= stay_stalled_for_gsf_din;
      
      //gsf
      always_ff @(posedge gclk.clk) begin
         nthreads <= dma2tm.threads_active+1;
  
         if(rst) begin
           ntokens <= 0;
           partition_credits <= dram_conf.credits;
           gsf_cycle_count <= dram_conf.cycles_per_gsf_frame;
         end    
         else if(run_reg && ntokens == nthreads) begin
          ntokens <= 0;
          
          if (gsf_cycle_count != 0)
            gsf_cycle_count <= gsf_cycle_count - 1;
          else
             partition_credits <= dram_conf.credits;      //reset credits
         end
         else if(dram_request.token_valid) begin
            ntokens <= ntokens+1;
    
            if (partition_queue_deq[dram_request.partitionid])
              partition_credits[dram_request.partitionid] <= partition_credits[dram_request.partitionid] - ((dram_request.writeback_valid) ? 1 : 2);
         end
      end

    
      
      generate
         genvar i;

         for(i = 0; i< NPARTITION; i++) begin
           replay_fifo  partition_queue (.*,.enq(dram_request.token_valid & dram_request.request_valid & (dram_request.partitionid == i)),.enq_data(dram_request.tid),.deq(partition_queue_deq[i]),.head(partition_queue_head[i]),.empty(partition_queue_empty[i]),.full());
        end        
         
         for(i = 0; i< MAX_MEMCONTROLLER; i++) begin
           dram_model_gsf tm_dram(.*, .dram_request(dram_request_gsf[i]), .stay_stalled_for_dram(stalled_for_dram[i]));
         end
            
      endgenerate
          
endmodule
*/

module dram_gsf_scheduler (input iu_clk_type gclk, input bit rst, input bit run_reg,
                   input dram_conf_t dram_conf,
                   input tm2cpu_token_type tm2cpu,
                   input dma_tm_ctrl_type dma2tm,
                   input tm_mem_request_t dram_request,
                   output bit 	stay_stalled_for_dram);
      bit[NTHREADIDMSB+1:0] ntokens,nthreads;

       (* syn_ramstyle = "select_ram" *) bit [NTHREAD-1:0]           stay_stalled_for_gsf;
       bit stay_stalled_for_gsf_we, stay_stalled_for_gsf_din;
       
       bit[log2x(MAX_MISS_PENALTY)-1:0]  partition_credits[NPARTITION-1:0];
       
       bit [NTHREADIDMSB+1:0]            partition_queue_head[0:NPARTITION-1];
       bit [NPARTITION-1:0]              partition_queue_deq, partition_queue_empty;
       
       bit                               has_credit_to_deq;
       
       bit       stalled_for_dram;
       
       tm_mem_request_t                  dram_request_gsf;
       
       bit[log2x(MAX_MISS_PENALTY)-1:0]  gsf_cycle_count;
       
      always_comb begin
        dram_request_gsf = dram_request;   //default value
        partition_queue_deq = '0;
        
        has_credit_to_deq = (partition_queue_head[dram_request.partitionid][NTHREADIDMSB:0] == dram_request.tid) & ((partition_credits[dram_request.partitionid] > 1 && dram_request.writeback_valid)  || (partition_credits[dram_request.partitionid] > 0 && !dram_request.writeback_valid));
        
        partition_queue_deq[dram_request.partitionid] =  has_credit_to_deq & dram_request.token_valid & ~partition_queue_empty[dram_request.partitionid];


        dram_request_gsf.request_valid = partition_queue_deq[dram_request.partitionid];
        dram_request_gsf.writeback_valid = dram_request_gsf.request_valid & partition_queue_head[NTHREADIDMSB+1];
        

        stay_stalled_for_dram = stalled_for_dram | stay_stalled_for_gsf[dram_request.tid];
                
        //stay_stalled_for_gsf
        stay_stalled_for_gsf_we = rst;
        stay_stalled_for_gsf_din = '0;
        
        if (dram_request.token_valid && !rst) begin
          if(dram_request.request_valid) begin      
            stay_stalled_for_gsf_we = '1;
            stay_stalled_for_gsf_din = '1;
          end
          else if (partition_queue_deq[dram_request.partitionid])
            stay_stalled_for_gsf_we = '1;
        end
      end
      
      //ram
      always_ff @(posedge gclk.clk) if (stay_stalled_for_gsf_we) stay_stalled_for_gsf[dram_request.tid] <= stay_stalled_for_gsf_din;
      
      //gsf
      always_ff @(posedge gclk.clk) begin
         nthreads <= dma2tm.threads_active+1;
  
         if(rst) begin
           ntokens <= 0;
           partition_credits <= dram_conf.credits;
           gsf_cycle_count <= dram_conf.cycles_per_gsf_frame;
         end    
         else if(run_reg && ntokens == nthreads) begin
           ntokens <= 0;
          
           if (gsf_cycle_count != 0) begin
             gsf_cycle_count <= gsf_cycle_count - 1;
           end
           else begin
             gsf_cycle_count <= dram_conf.cycles_per_gsf_frame;
             partition_credits <= dram_conf.credits;      //reset credits
           end
         end
         else if(dram_request.token_valid) begin
            ntokens <= ntokens+1;
            
            if (partition_queue_deq[dram_request.partitionid]) begin
              partition_credits[dram_request.partitionid] <= partition_credits[dram_request.partitionid] - ((dram_request.writeback_valid) ? 2 : 1);
              $display("Now partition %d has %d credits",dram_request.partitionid,partition_credits[dram_request.partitionid] - ((dram_request.writeback_valid) ? 2 : 1));
            end
         end
      end

    
      
      generate
         genvar i;

         for(i = 0; i< NPARTITION; i++) begin
           replay_fifo #(.WIDTH(NTHREADIDMSB+2)) partition_queue (.*,.enq(dram_request.token_valid & dram_request.request_valid & (dram_request.partitionid == i)),.enq_data({dram_request.writeback_valid,dram_request.tid}),.deq(partition_queue_deq[i]),.head(partition_queue_head[i]),.empty(partition_queue_empty[i]),.full());
        end
      endgenerate
      
      dram_model_fast tm_dram(.*, .dram_request(dram_request_gsf), .stay_stalled_for_dram(stalled_for_dram));
          
endmodule