//---------------------------------------------------------------------------   
// File:        blkmemctrl.v
// Author:      Zhangxi Tan
// Description: The simplest blockram memory controller
//------------------------------------------------------------------------------

// **************************************BRAM memory timing ***********************************************
//
//        |<-------------M1------------>|<-------------M2------------>|<------------XC------------->|
//
// clk     ______________                ______________                ______________
//        |              |              |              |              |              |
//                       ----------------              ----------------              ----------------
//         _______        _______        _______        _______        _______        _______
// clk2x  |       |      |       |      |       |      |       |      |       |      |       |
//                --------       --------       --------       --------       --------       --------
//
// BRAM signals
//           <-----------raddr------------>
//                        ^-------------------------------------------------sampled by clk2x bram
//                                         <-----------dout------------>
//
// track return info 
//           <----------r_ret[0]----------><----------r_ret[1]--------->
//           
//                                       

`timescale 1ns / 1ps

`ifndef SYNP94
import libconf::*;
import libstd::*;
import libiu::*;
import libmemif::*;
import libcache::*;
`else
`include "../cpu/libiu.sv"
`include "../cpu/libmmu.sv"
`include "../cpu/libcache.sv"
`include "libmemif.sv"
`endif

`ifdef SYNP94
//`ifdef testSYNP
function automatic bit [log2x(NMEMCTRLPORT*2)-1:0] find_next_port(mem_ctrl_in_type port_buf[0:2*NMEMCTRLPORT-1], bit [log2x(NMEMCTRLPORT*2)-1:0]	cur_port);
	bit [log2x(NMEMCTRLPORT*2)-1:0]		ilo, ihi;	//temp result
	bit has_lo, has_hi;	
	
	has_lo = '0; has_hi = '0;
	ilo = '0; ihi = '0;

	for (int i=0;i<NMEMCTRLPORT*2;i++) begin
		//search for low		
		if (i <= cur_port && port_buf[i].s1.valid == 1'b1 && has_lo == 1'b0) begin
			has_lo = 1'b1;
			ilo = i;
		end
		
		//search for hi
		if (i > cur_port && port_buf[i].s1.valid == 1'b1 && has_hi == 1'b0) begin
			has_hi = 1'b1;
			ihi = i;
		end
	end

	if (has_hi) 
		return ihi;
	else if (has_lo)
		return ilo;
	else
//	  return (cur_port + 1) % (NMEMCTRLPORT*2);       //RR with skip
     return cur_port;                                //park

endfunction
                                    

module blkmemctrl(input iu_clk_type gclk, input rst,
	                input  mem_ctrl_in_type  imem_in[0:NMEMCTRLPORT-1],
		              input  mem_ctrl_in_type  dmem_in[0:NMEMCTRLPORT-1],
		              output mem_ctrl_out_type imem_out[0:NMEMCTRLPORT-1],
		              output mem_ctrl_out_type dmem_out[0:NMEMCTRLPORT-1]);
	
	bit [log2x(NMEMCTRLPORT*2)-1:0]		cur_port, v_cur_port;		//current port
	bit [log2x(NMEMCTRLPORT*2)-1:0]		next_port;			          //next port	
	
	
	//int	i;			//loop variables		
	
  typedef enum bit {BURST1 = 1'b0, BURST2 = 1'b1} memctrl_state_type;
	
	memctrl_state_type			         vstate, rstate;	
	bit [2*NMEMCTRLPORT-1:0]     	new_credit;    //credit feedback
	
	//mem_ctrl_in_type  v_port_buf[0:1][0:2*NMEMCTRLPORT-1], r_port_buf[0:1][0:2*NMEMCTRLPORT-1];
	mem_ctrl_in_type  v_port_buf_0[0:2*NMEMCTRLPORT-1], v_port_buf_1[0:2*NMEMCTRLPORT-1];
	mem_ctrl_in_type  r_port_buf_0[0:2*NMEMCTRLPORT-1], r_port_buf_1[0:2*NMEMCTRLPORT-1];
	
//	mem_ctrl_in_type  tmp_0, tmp_1, tmp_2, tmp_3, tmp_4;
	
	cache_data_type					        din, rdin, dout;			
	bit [31:ICACHEINDEXLSB_IU]		addr, raddr;
	bit								            we, rwe;
	
	//buffer return address
	typedef struct {		
		bit [NTHREADIDMSB:0]				tid;
//		bit					tid_index_parity;		//used for parity generation in lutram fifo in memctrl
		struct packed{
			bit [ICACHEINDEXMSB_IU:ICACHEINDEXLSB_IU]	I;
			bit [DCACHEINDEXMSB_IU:DCACHEINDEXLSB_IU]	D;
		}ret_index;		//write back block index;	

		bit  valid;  //result is valid
		bit  done;   //done signal
	}mem_return_type;		//return address and etc.

	//mem_return_type						v_ret[0:2][0:2*NMEMCTRLPORT-1], r_ret[0:2][0:2*NMEMCTRLPORT-1];	//return register	
	mem_return_type							v_ret_0[0:2*NMEMCTRLPORT-1], v_ret_1[0:2*NMEMCTRLPORT-1];
	mem_return_type							r_ret_0[0:2*NMEMCTRLPORT-1], r_ret_1[0:2*NMEMCTRLPORT-1];	//return register	
//	mem_return_type							tmp_ret, tmp_ret_r;

  //input buffer
  always_comb begin
  //    foreach(r_ret[i]) begin
      for(int i=0;i<2*NMEMCTRLPORT;i++) begin   	
        if (new_credit[i] == 1'b1 || r_port_buf_0[i].s1.valid == 1'b0 || r_port_buf_1[i].s1.valid == 1'b0)
          v_port_buf_0[i] = (i%2) ? dmem_in[i/2] : imem_in[i/2];
	      else
          v_port_buf_0[i] = r_port_buf_0[i];
      end
      
  //    foreach(r_ret[i]) begin
       for(int i=0;i<2*NMEMCTRLPORT;i++) begin    
        if (new_credit[i] == 1'b1 || r_port_buf_1[i].s1.valid == 1'b0) 
	        v_port_buf_1[i] = r_port_buf_0[i];	  	 	  
        else
	        v_port_buf_1[i] = r_port_buf_1[i];
      end
  
  end
 

  function automatic mem_ctrl_in_type get_port_buf(mem_ctrl_in_type vbuf);
      mem_ctrl_in_type  rbuf;
      rbuf = vbuf;
      
       if (rst)
        rbuf.s1.valid = '0;

      return rbuf;
  endfunction
  
  always_ff @(posedge gclk.clk) begin
    for (int i=0;i<2*NMEMCTRLPORT;i++) begin
       r_port_buf_0[i] <= get_port_buf(v_port_buf_0[i]);
       r_port_buf_1[i] <= get_port_buf(v_port_buf_1[i]);
    end
  end

/*
  always @(posedge gclk.clk) begin
    for (int i=0;i<2*NMEMCTRLPORT;i++) begin
       r_port_buf_0[i] = v_port_buf_0[i];
       r_port_buf_1[i] = v_port_buf_1[i];
       
       if (rst) begin
         r_port_buf_0[i].s1.valid = '0;
         r_port_buf_1[i].s1.valid = '0;
       end
    end
  end
*/
  //main FSM
  always_comb begin
     vstate     = rstate;
     v_cur_port = cur_port;
     next_port  = find_next_port(r_port_buf_1, cur_port);      //next available port
	  

/*
	 tmp_3 = r_port_buf_1[cur_port];
     din  = tmp_3.s2.data;
     addr = (cur_port[0])?{tmp_3.s2.addr_prefix.D, tmp_3.s1.ret_index.D, 1'b0}:{tmp_3.s2.addr_prefix.I, tmp_3.s1.ret_index.I, 1'b0};
     we   = tmp_3.s1.we;
*/ 

     din  = r_port_buf_1[cur_port].s2.data;
     addr = (cur_port[0])?{r_port_buf_1[cur_port].s2.addr_prefix.D, r_port_buf_1[cur_port].s1.ret_index.D, 1'b0}:{r_port_buf_1[cur_port].s2.addr_prefix.I, r_port_buf_1[cur_port].s1.ret_index.I, 1'b0};
     we   = r_port_buf_1[cur_port].s1.we;

    //buffered return information & flow control
    	
	//foreach (imem_in[i]) begin
	 for(int i=0;i<NMEMCTRLPORT;i++) begin
     	v_ret_0[i*2].tid         = r_port_buf_1[i*2].s1.tid;
		v_ret_0[i*2].ret_index.I = {r_port_buf_1[i*2].s1.ret_index.I, 1'b0};
		v_ret_0[i*2].valid       = '0;	
		v_ret_0[i*2].done        = '0;


		v_ret_0[i*2+1].tid         = r_port_buf_1[i*2+1].s1.tid;
		v_ret_0[i*2+1].ret_index.D = {r_port_buf_1[i*2+1].s1.ret_index.D, 1'b0};
		v_ret_0[i*2+1].valid       = '0;
		v_ret_0[i*2+1].done        = '0;

		new_credit[2*i]   = '0;
		new_credit[2*i+1] = '0;

	  v_ret_1[i*2]   = r_ret_0[i*2];
   	v_ret_1[i*2+1] = r_ret_0[i*2+1];
   end
   
   unique case (rstate) 
	 BURST1: begin	 		
//                 if (tmp_3.s1.valid) begin				 				 
	              if (r_port_buf_1[cur_port].s1.valid) begin				 				 
                   vstate                   = BURST2;				   
                   
                   v_ret_0[cur_port].valid = ~we;
				   new_credit[cur_port]    = '1;
/*
                   for (int j=0;j<2*NMEMCTRLPORT;j++) begin
					   if (cur_port == j) begin
		                   v_ret_0[j].valid = ~we;
						   new_credit[j]    = '1;
					   end
	               end      
*/	                           
                 end
                 else
                   v_cur_port = next_port;
	         end
   BURST2: begin
                 vstate     = BURST1;
                 v_cur_port = next_port;
                                  
                 addr = addr | 1;

                // foreach (v_ret[i]) begin
                 for(int i=0;i<2*NMEMCTRLPORT;i++) begin
             			
              			if (i % 2) 
                   			v_ret_0[i].ret_index.D = v_ret_0[i].ret_index.D | 1;
                 		else
                   			v_ret_0[i].ret_index.I = v_ret_0[i].ret_index.I | 1;	                   		
                 end

	               	v_ret_0[cur_port].valid = ~we;
    	           	v_ret_0[cur_port].done  = '1;
                	
        	       	new_credit[cur_port]    = '1;

/*
				   for (int j=0; j<2*NMEMCTRLPORT;j++) begin
                	if (j==cur_port) begin
	                	v_ret_0[j].valid = ~we;
    	            	v_ret_0[j].done  = '1;
                	
        	        	new_credit[j]    = '1;
                	end
                  end */
             end
   endcase

  end
   
  
  function automatic mem_return_type get_r_ret(mem_return_type v);
    // delay register
       mem_return_type r;

       r = v;
       
       if (rst) begin 
         r.valid = '0;          
         r.done = '0;
       end   
       
       return r; 	
  endfunction
  
  //track return cache blk index
  always_ff @(posedge gclk.clk) begin
      //non-block assignment must be used in some form to prevent event race.       
      //get_r_ret();    //will cause event race 
      for(int i=0;i<2*NMEMCTRLPORT;i++) begin
           r_ret_0[i] <= get_r_ret(v_ret_0[i]);
           r_ret_1[i] <= get_r_ret(v_ret_1[i]);
      end
  end
  
  
  always_ff @(posedge gclk.clk) begin
      //state control and port selector
  	   /*rstate   <= (rst) ? BURST1 : vstate;
	    cur_port <= (rst)? '0 : v_cur_port;	*/           //precision doesn't like conditional operator for set/reset
      if (rst) rstate   <= BURST1; else rstate   <= vstate;
	    if (rst) cur_port <= '0;     else cur_port <= v_cur_port;					

      //input registers to bram
      rdin  <= din;
      raddr <= addr;             
      //rwe   <= (rst) ? '0 : we;
      if (rst) rwe <= '0; else rwe <= we;
  end
  
  function automatic mem_ctrl_out_type get_mem_out(mem_return_type retin, bit credit);
	mem_ctrl_out_type	tmp_res;

	tmp_res.res.tid  		= retin.tid;
	tmp_res.res.ret_index.I = retin.ret_index.I;
	tmp_res.res.ret_index.D = retin.ret_index.D;
	
	tmp_res.res.data = dout;
	
	if (rst) begin
		tmp_res.res.valid 	= '0;	
		tmp_res.res.done 	= '0;
		tmp_res.ctrl.cmd_re = '0;
	end
	else begin
		tmp_res.res.valid 	= retin.valid;	
		tmp_res.res.done 	= retin.done;
		tmp_res.ctrl.cmd_re = unsigned'(credit);		
	end

	return tmp_res;
  endfunction 
  
  //output registers
  always_ff @(posedge gclk.clk) begin  
//   foreach(imem_out[i]) begin
     for(int i=0;i<NMEMCTRLPORT;i++) begin
      //result registers
	  imem_out[i] <= get_mem_out(r_ret_1[2*i], new_credit[2*i]);
	  dmem_out[i] <= get_mem_out(r_ret_1[2*i+1], new_credit[2*i+1]);
    end
  end
  
	
	//8K configuration uses 9 address line, ADDRMSB = 8
	//32K configuration uses 11 address line, ADDRMSB = 10
	bram_memory_128 #(.ADDRMSB(10)) bm_blocks(.gclk, .rst,
		 		  .addr(raddr[ICACHEINDEXLSB_IU+10:ICACHEINDEXLSB_IU]),    
		 		  .we(rwe),		  //write enable
				  .din(rdin),		//data in
		 		  .dout		      //data out
          );
endmodule

`else
function automatic bit [log2x(NMEMCTRLPORT*2)-1:0] find_next_port(mem_ctrl_in_type port_buf[0:2*NMEMCTRLPORT-1], bit [log2x(NMEMCTRLPORT*2)-1:0]	cur_port);
	bit [log2x(NMEMCTRLPORT*2)-1:0]		ilo, ihi;	//temp result
	bit has_lo, has_hi;	

	has_lo = '0; has_hi = '0;
	ilo = '0; ihi = '0;

	for (int i=0;i<NMEMCTRLPORT*2;i++) begin
		//search for low		
		if (i <= cur_port && port_buf[i].s1.valid == 1'b1 && has_lo == 1'b0) begin
			has_lo = 1'b1;
			ilo = i;
		end
		
		//search for hi
		if (i > cur_port && port_buf[i].s1.valid == 1'b1 && has_hi == 1'b0) begin
			has_hi = 1'b1;
			ihi = i;
		end
	end

	if (has_hi) 
		return ihi;
	else if (has_lo)
		return ilo;
//	else if (port_buf[cur_port].s1.valid)
//		return cur_port;
	else
	  //return (cur_port + 1) % (NMEMCTRLPORT*2);       //RR with skip
	  return cur_port;                                  //park

endfunction
                                    

module blkmemctrl(input iu_clk_type gclk, input rst,
	                input  mem_ctrl_in_type  imem_in[0:NMEMCTRLPORT-1],
		              input  mem_ctrl_in_type  dmem_in[0:NMEMCTRLPORT-1],
		              output mem_ctrl_out_type imem_out[0:NMEMCTRLPORT-1],
		              output mem_ctrl_out_type dmem_out[0:NMEMCTRLPORT-1]);
	
	bit [log2x(NMEMCTRLPORT*2)-1:0]		cur_port, v_cur_port;		//current port
	bit [log2x(NMEMCTRLPORT*2)-1:0]		next_port;			          //next port	
	
	
	//int	i;			//loop variables		
	
  typedef enum bit {BURST1 = 1'b0, BURST2 = 1'b1} memctrl_state_type;
	
	memctrl_state_type			         vstate, rstate;	
	bit [2*NMEMCTRLPORT-1:0]     	new_credit;    //credit feedback
	
	mem_ctrl_in_type  v_port_buf[0:1][0:2*NMEMCTRLPORT-1], r_port_buf[0:1][0:2*NMEMCTRLPORT-1];
	
	cache_data_type					        din, rdin, dout;			
	bit [31:ICACHEINDEXLSB_IU]		addr, raddr;
	bit								            we, rwe;
	
	//buffer return address
	typedef struct {		
		bit [NTHREADIDMSB:0]				tid;
//		bit					tid_index_parity;		//used for parity generation in lutram fifo in memctrl
		union packed{
			bit [ICACHEINDEXMSB_IU:ICACHEINDEXLSB_IU]	I;
			bit [DCACHEINDEXMSB_IU:DCACHEINDEXLSB_IU]	D;
		}ret_index;		//write back block index;	

		bit  valid;  //result is valid
		bit  done;   //done signal
	}mem_return_type;		//return address and etc.

	mem_return_type						v_ret[0:1][0:2*NMEMCTRLPORT-1], r_ret[0:1][0:2*NMEMCTRLPORT-1];	//return register	

  //input buffer
  always_comb begin
  //    foreach(r_ret[i]) begin
      for(int i=0;i<2*NMEMCTRLPORT;i++) begin
        if (new_credit[i] == 1'b1 || r_port_buf[0][i].s1.valid == 1'b0 || r_port_buf[1][i].s1.valid == 1'b0)
          v_port_buf[0][i] = (i%2) ? dmem_in[i/2] : imem_in[i/2];
	      else
          v_port_buf[0][i] = r_port_buf[0][i];
        
     //   if (rst) 
     //     v_port_buf[0][i].s1.valid = '0;
      end
      
  //    foreach(r_ret[i]) begin
       for(int i=0;i<2*NMEMCTRLPORT;i++) begin
        if (new_credit[i] == 1'b1 || r_port_buf[1][i].s1.valid == 1'b0) 
	        v_port_buf[1][i] = r_port_buf[0][i];	  	 	  
        else
          v_port_buf[1][i] = r_port_buf[1][i];
            
     //   if (rst) 
     //      v_port_buf[1][i].s1.valid = '0;
      end
  
  end
 

  function automatic mem_ctrl_in_type get_port_buf(mem_ctrl_in_type vbuf);
      mem_ctrl_in_type  rbuf = vbuf;
      
       if (rst)
        rbuf.s1.valid = '0;

      return rbuf;
  endfunction
  
  always_ff @(posedge gclk.clk) begin
    for (int i=0;i<2*NMEMCTRLPORT;i++) begin
       r_port_buf[0][i] <= get_port_buf(v_port_buf[0][i]);
       r_port_buf[1][i] <= get_port_buf(v_port_buf[1][i]);
    end
  end

/*
  always @(posedge gclk.clk) begin
    for (int i=0;i<2*NMEMCTRLPORT;i++) begin
       r_port_buf[0][i] = v_port_buf[0][i];
       r_port_buf[1][i] = v_port_buf[1][i];
       
       if (rst) begin
         r_port_buf[0][i].s1.valid = '0;
         r_port_buf[1][i].s1.valid = '0;
       end
    end
  end
*/
  //main FSM
  always_comb begin
     vstate     = rstate;
     v_cur_port = cur_port;
     next_port  = find_next_port(r_port_buf[1], cur_port);      //next available port
	  

     //din  = r_port_buf[1][cur_port].s2.data;
     //addr = {r_port_buf[1][cur_port].s2.addr_prefix, r_port_buf[1][cur_port].s1.ret_index, 1'b0};
     //we   = r_port_buf[1][cur_port].s1.we;
     
     din  = r_port_buf[1][cur_port].s2.data;
     addr = (cur_port[0])? {r_port_buf[1][cur_port].s2.addr_prefix.D, r_port_buf[1][cur_port].s1.ret_index.D, 1'b0} : {r_port_buf[1][cur_port].s2.addr_prefix.I, r_port_buf[1][cur_port].s1.ret_index.I, 1'b0};
     we   = r_port_buf[1][cur_port].s1.we;

    //buffered return information & flow control
    	
	//foreach (imem_in[i]) begin
	 for(int i=0;i<NMEMCTRLPORT;i++) begin
	  v_ret[0][i*2].tid         = r_port_buf[1][i*2].s1.tid;
		v_ret[0][i*2].ret_index.I = {r_port_buf[1][i*2].s1.ret_index.I, 1'b0};
		v_ret[0][i*2].valid       = '0;	
		v_ret[0][i*2].done        = '0;

		v_ret[0][i*2+1].tid         = r_port_buf[1][i*2+1].s1.tid;
		v_ret[0][i*2+1].ret_index.D = {r_port_buf[1][i*2+1].s1.ret_index.D, 1'b0};
		v_ret[0][i*2+1].valid       = '0;
		v_ret[0][i*2+1].done        = '0;

		new_credit[2*i]   = '0;
		new_credit[2*i+1] = '0;

    v_ret[1][i*2]   = r_ret[0][i*2];
    v_ret[1][i*2+1] = r_ret[0][i*2+1];
    
//    v_ret[2][i*2]   = r_ret[1][i*2];
//    v_ret[2][i*2+1] = r_ret[1][i*2+1];
	end
   
        	 
   unique case (rstate) 
	 BURST1: begin	 		
                 if (r_port_buf[1][cur_port].s1.valid) begin				 				 
                   vstate                   = BURST2;				   
                   v_ret[0][cur_port].valid = !we;
				           new_credit[cur_port]     = '1;
                 end
                 else
                   v_cur_port = next_port;
	         end
   BURST2: begin
	               vstate     = BURST1;
                 v_cur_port = next_port;
                                  
                 addr = addr | 1;

                // foreach (v_ret[i]) begin
                 for(int i=0;i<2*NMEMCTRLPORT;i++) begin
            			  //v_ret[i].tid = r_ret[i].tid;
	                
            					//v_ret[i].ret_index = v_ret[i].ret_index | 1;
					
              			if (i % 2) 
                   			v_ret[0][i].ret_index.D = v_ret[0][i].ret_index.D | 1;
                 		else
                   			v_ret[0][i].ret_index.I = v_ret[0][i].ret_index.I | 1;					
                 end

                	v_ret[0][cur_port].valid = !we;
                	v_ret[0][cur_port].done  = '1;
                	new_credit[cur_port]     = '1;
             end
   endcase

  end
 
 /* 
  task automatic get_r_ret();
    // delay register
     for(int i=0;i<2*NMEMCTRLPORT;i++) begin
       r_ret[0][i] = v_ret[0][i];
       r_ret[1][i] = v_ret[1][i];
       r_ret[2][i] = v_ret[2][i];
       
       if (rst) begin 
         r_ret[0][i].valid = '0;    
         r_ret[1][i].valid = '0;
         r_ret[2][i].valid = '0;
         
         r_ret[0][i].done = '0;
         r_ret[1][i].done = '0;
         r_ret[2][i].done = '0;
       end
     end      	
  endtask
  */

  function automatic mem_return_type get_r_ret(mem_return_type v);
    // delay register
       mem_return_type r;

       r = v;
       
       if (rst) begin 
         r.valid = '0;          
         r.done = '0;
       end   
       
       return r; 	
  endfunction
  
  //track return cache blk index
  always_ff @(posedge gclk.clk) begin
      //non-block assignment must be used in some form to prevent event race.       
      //get_r_ret();    //will cause event race 
      for(int i=0;i<2*NMEMCTRLPORT;i++) begin
           r_ret[0][i] <= get_r_ret(v_ret[0][i]);
           r_ret[1][i] <= get_r_ret(v_ret[1][i]);
//           r_ret[2][i] <= get_r_ret(v_ret[2][i]);           
      end
  end
  
  always_ff @(posedge gclk.clk) begin
      //state control and port selector
  	   /*rstate   <= (rst) ? BURST1 : vstate;
	    cur_port <= (rst)? '0 : v_cur_port;	*/           //precision doesn't like conditional operator for set/reset
      if (rst) rstate   <= BURST1; else rstate   <= vstate;
	    if (rst) cur_port <= '0;     else cur_port <= v_cur_port;					

      //input registers to bram
      rdin  <= din;
      raddr <= addr;             
      //rwe   <= (rst) ? '0 : we;
      if (rst) rwe <= '0; else rwe <= we;
  end
  
  //output registers
  always_ff @(posedge gclk.clk) begin  
     for(int i=0;i<NMEMCTRLPORT;i++) begin  
      //result registers      
      imem_out[i].res.tid         <= r_ret[1][2*i].tid;
      imem_out[i].res.ret_index.I <= r_ret[1][2*i].ret_index.I;
      dmem_out[i].res.tid         <= r_ret[1][2*i+1].tid;
      dmem_out[i].res.ret_index.D <= r_ret[1][2*i+1].ret_index.D;					
    
      imem_out[i].res.data <= dout;
      dmem_out[i].res.data <= dout;

      /*
      imem_out[i].res.valid <= (rst) ? '0 : r_ret[1][2*i].valid;
      dmem_out[i].res.valid <= (rst) ? '0 : r_ret[1][2*i+1].valid;
  
      //command fifo RE control
      imem_out[i].ctrl.cmd_re <= (rst) ? '0 : new_credit[2*i];
      dmem_out[i].ctrl.cmd_re <= (rst) ? '0 : new_credit[2*i+1]; */         //precision doesn't like this
      
      if (rst) begin
        imem_out[i].res.valid   <= '0;
        imem_out[i].res.done    <= '0;
        dmem_out[i].res.valid   <= '0;
        dmem_out[i].res.done    <= '0;
        
  
        //command fifo RE control
        imem_out[i].ctrl.cmd_re <= '0;
        dmem_out[i].ctrl.cmd_re <= '0; 
      end
      else begin
        imem_out[i].res.valid   <= r_ret[1][2*i].valid;
        imem_out[i].res.done    <= r_ret[1][2*i].done;
        dmem_out[i].res.valid   <= r_ret[1][2*i+1].valid;
        dmem_out[i].res.done    <= r_ret[1][2*i+1].done;
        
  
        //command fifo RE control
        imem_out[i].ctrl.cmd_re <= unsigned'(new_credit[2*i]);
        dmem_out[i].ctrl.cmd_re <= unsigned'(new_credit[2*i+1]);
      end
    end
  end
  
	
	//8K configuration uses 9 address line, ADDRMSB = 8
	//32K configuration uses 11 address line, ADDRMSB = 10
	bram_memory_128 #(.ADDRMSB(10)) bm_blocks(.gclk, .rst,
		 		  .addr(raddr[ICACHEINDEXLSB_IU+10:ICACHEINDEXLSB_IU]),    
		 		  .we(rwe),		  //write enable
				  .din(rdin),		//data in
		 		  .dout		      //data out
          );
endmodule
`endif