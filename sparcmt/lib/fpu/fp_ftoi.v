`timescale 1ns / 1ps

module fp_stoi(
    input clk,
    input rst,
    input en,
    input [31:0] din,
    output reg [31:0] dout,
    output reg rdy,
    output reg overflow,
    output reg invalid_op );
    
    wire sign;
    wire [7:0] exp;
    wire [22:0] mantissa;
    wire [31:0] significand;
    
    reg [4:0] sign_r;
    reg [7:0] exp_r[4:0];
    reg [9:0] index_r[2:0];
    wire [31:0] significand_i[2:0];
    reg [31:0] significand_r[4:0];
    reg [4:0] en_r;
    reg [4:0] mantissa_zero_r;
    
    reg carry;

    assign sign = din[31];
    assign exp = din[30:23];
    assign mantissa = din[22:0];
    assign significand = {1'b1,mantissa,8'h00};

    // 3 stages for 32 bit barrel shifter
    // 2 4:1 and 1 2:1
    mux4x1 #(.DWIDTH(32))
           m1 (.a(significand_r[0]), 
               .b({8'h00, significand_r[0][31:8]}),
               .c({16'h0000, significand_r[0][31:16]}),
               .d({24'h000000, significand_r[0][31:24]}),
               .sel(index_r[0][4:3]),
               .out(significand_i[0]));
               
    mux4x1 #(.DWIDTH(32))
           m2 (.a(significand_r[1]), 
               .b({2'b00,significand_r[1][31:2]}),
               .c({4'b0000, significand_r[1][31:4]}),
               .d({6'b000000, significand_r[1][31:6]}),
               .sel(index_r[1][2:1]),
               .out(significand_i[1])); 
               
    assign significand_i[2] = index_r[2][0] ? {1'b0, significand_r[2][31:1]} : significand_r[2];
                                        
    always @(posedge clk, posedge rst)
    begin
      if (rst)
      begin
        en_r <= 0;
      end
      else
      begin
        // first pipeline stage
        // compute shift amount
        index_r[0] <= (127 - exp + 31);
        sign_r[0] <= sign;
        significand_r[0] <= significand;
        en_r[0] <= en;
        mantissa_zero_r[0] <= (mantissa == 0);
        exp_r[0] <= exp;
        
        // second pipeline stage
        // start barrel shifting
        
        if (index_r[0] > 0 && index_r[0] < 33)
            significand_r[1] <= significand_i[0];
        else
            significand_r[1] <= significand_r[0];
        
        index_r[1] <= index_r[0];
        sign_r[1] <= sign_r[0];
        en_r[1] <= en_r[0];
        mantissa_zero_r[1] <= mantissa_zero_r[0];
        exp_r[1] <= exp_r[0];

        // third pipeline stage
        // keep shifting
        
        if (index_r[1] > 0 && index_r[1] < 33)
            significand_r[2] <= significand_i[1];
        else
            significand_r[2] <= significand_r[1];
            
        index_r[2] <= index_r[1];
        sign_r[2] <= sign_r[1];
        en_r[2] <= en_r[1];
        mantissa_zero_r[2] <= mantissa_zero_r[1];
        exp_r[2] <= exp_r[1];
        
        // fourth pipeline stage
        // finish up shifting
        
        if (index_r[2] > 0 && index_r[2] < 33)
            significand_r[3] <= significand_i[2];
        else
            significand_r[3] <= significand_r[2];

        sign_r[3] <= sign_r[2];
        en_r[3] <= en_r[2];
        mantissa_zero_r[3] <= mantissa_zero_r[2];
        exp_r[3] <= exp_r[2];
                  
        // fifth pipeline stage
        
        if (sign_r[3]) // negative values
            {carry, significand_r[4]} <= ~significand_r[3]+1;
        else // positive values
            significand_r[4] <= significand_r[3];
        
        sign_r[4] <= sign_r[3];
        en_r[4] <= en_r[3];
        mantissa_zero_r[4] <= mantissa_zero_r[3];
        exp_r[4] <= exp_r[3];
        
        // sixth pipeline stage
        
        rdy <= en_r[4];
        if (exp_r[4] == 0) // zero or subnormal numbers
        begin
            invalid_op <= 1'b0;
            overflow <= 1'b0;
            dout <= {32{1'b0}};
        end
        else if (exp_r[4] == 255) // infinities or NaNs
        begin
            invalid_op <= 1'b1;
            if (mantissa_zero_r[4])
            begin
                overflow <= 1'b1;
                if (sign_r[4])
                    dout <= {1'b1, {31{1'b0}}};
                else
                    dout <= {1'b0, {31{1'b1}}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= {1'b0, {31{1'b1}}};
            end 
        end
        else if (sign_r[4])  // negative values 
        begin
            invalid_op <= 1'b0;
            // if exponent >= 158, set the output to minimum value and signal
            // overflow, unless exponent is 158 and mantissa is 0
            if (exp_r[4] >= 158)
            begin
                dout <= {1'b1, {31{1'b0}}};
                if ((exp_r[4] == 158) && mantissa_zero_r[4])
                    overflow <= 1'b0;
                else
                    overflow <= 1'b1;
            end
            // round to zero if exponent is 126 or lower
            else if (exp_r[4] <= 126)
            begin
                overflow <= 1'b0;
                dout <= {32{1'b0}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= significand_r[4];
            end
        end
        else // positive values
        begin //signal overflow if exponent >= 158
            invalid_op <= 1'b0;
            if (exp_r[4] >= 158)
            begin
                overflow <= 1'b1;
                dout <= {1'b0, {31{1'b1}}};
            end
            // round to zero if exponent is 126 or lower
            else if (exp_r[4] <= 126)
            begin
                overflow <= 1'b0;
                dout <= {32{1'b0}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= significand_r[4];
            end  
        end
      end
    end       

endmodule

module fp_dtoi(
    input clk,
    input rst,
    input en,
    input [63:0] din,
    output reg [31:0] dout,
    output reg rdy,
    output reg overflow,
    output reg invalid_op );
    
    wire sign;
    wire [10:0] exp;
    wire [51:0] mantissa;
    wire [63:0] significand;
    
    reg [4:0] sign_r;
    reg [10:0] exp_r[4:0];
    reg [12:0] index_r[2:0];
    wire [63:0] significand_i[2:0];
    reg [63:0] significand_r[4:0];
    reg [4:0] en_r;
    reg [4:0] mantissa_zero_r;
    
    reg carry;
        
    assign sign = din[63];
    assign exp = din[62:52];
    assign mantissa = din[51:0];
    assign significand = {1'b1,mantissa,11'h000};

    // 3 stages for 64 bit barrel shifter
    
    mux4x1 #(.DWIDTH(64))
           m1 (.a(significand_r[0]), 
               .b({16'h0000, significand_r[0][63:16]}),
               .c({32'h00000000, significand_r[0][63:32]}),
               .d({48'h000000000000, significand_r[0][63:48]}),
               .sel(index_r[0][5:4]),
               .out(significand_i[0]));
               
    mux4x1 #(.DWIDTH(64))    
           m2 (.a(significand_r[1]), 
               .b({4'h0,significand_r[1][63:4]}),
               .c({8'h00, significand_r[1][63:8]}),
               .d({12'h000, significand_r[1][63:12]}),
               .sel(index_r[1][3:2]),
               .out(significand_i[1])); 

    mux4x1 #(.DWIDTH(64))
           m3 (.a(significand_r[2]), 
               .b({1'b0,significand_r[2][63:1]}),
               .c({2'b00, significand_r[2][63:2]}),
               .d({3'b000, significand_r[2][63:3]}),
               .sel(index_r[2][1:0]),
               .out(significand_i[2])); 
                                        
    always @(posedge clk, posedge rst)
    begin
      if (rst)
      begin
        en_r <= 0;
      end
      else
      begin
        // first pipeline stage
        // comput shift amount
        index_r[0] <= (1023 - exp + 63);
        sign_r[0] <= sign;
        significand_r[0] <= significand;
        en_r[0] <= en;
        mantissa_zero_r[0] <= (mantissa == 52'h0000000000000);
        exp_r[0] <= exp;
        
        // second pipeline stage
        // start barrel shifting
        
        if (index_r[0] > 0 && index_r[0] < 65)
            significand_r[1] <= significand_i[0];
        else
            significand_r[1] <= significand_r[0];
        
        index_r[1] <= index_r[0];
        sign_r[1] <= sign_r[0];
        en_r[1] <= en_r[0];
        mantissa_zero_r[1] <= mantissa_zero_r[0];
        exp_r[1] <= exp_r[0];

        // third pipeline stage
        // keep shifting
        
        if (index_r[1] > 0 && index_r[1] < 65)
            significand_r[2] <= significand_i[1];
        else
            significand_r[2] <= significand_r[1];
            
        index_r[2] <= index_r[1];
        sign_r[2] <= sign_r[1];
        en_r[2] <= en_r[1];
        mantissa_zero_r[2] <= mantissa_zero_r[1];
        exp_r[2] <= exp_r[1];
        
        // fourth pipeline stage
        // finish up shifting
        
        if (index_r[2] > 0 && index_r[2] < 65)
            significand_r[3] <= significand_i[2];
        else
            significand_r[3] <= significand_r[2];

        sign_r[3] <= sign_r[2];
        en_r[3] <= en_r[2];
        mantissa_zero_r[3] <= mantissa_zero_r[2];
        exp_r[3] <= exp_r[2];
                  
        // fifth pipeline stage
        
        if (sign_r[3]) // negative values
            {carry, significand_r[4]} <= ~significand_r[3]+1;
        else // positive values
            significand_r[4] <= significand_r[3];
        
        sign_r[4] <= sign_r[3];
        en_r[4] <= en_r[3];
        mantissa_zero_r[4] <= mantissa_zero_r[3];
        exp_r[4] <= exp_r[3];
        
        // sixth pipeline stage
        
        rdy <= en_r[4];
        if (exp_r[4] == 0) // zero (or subnormal) numbers
        begin
            invalid_op <= 1'b0;
            overflow <= 1'b0;
            dout <= {32{1'b0}};
        end
        else if (exp_r[4] == 2047) // infinities or NaNs
        begin
            invalid_op <= 1'b1;
            if (mantissa_zero_r[4])
            begin
                overflow <= 1'b1;
                if (sign_r[4])
                    dout <= {1'b1, {31{1'b0}}};
                else
                    dout <= {1'b0, {31{1'b1}}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= {1'b0, {31{1'b1}}};
            end 
        end
        else if (sign_r[4])  // negative values 
        begin
            invalid_op <= 1'b0;
            // if exponent >= 1054, set the output to minimum value and signal
            // overflow, unless exponent is 1054 and mantissa is 0
            if (exp_r[4] >= 1054)
            begin
                dout <= {1'b1, {31{1'b0}}};
                if ((exp_r[4] == 1054) && mantissa_zero_r[4])
                    overflow <= 1'b0;
                else
                    overflow <= 1'b1;
            end
            // round to zero if exponent is 1022 or lower
            else if (exp_r[4] <= 1022)
            begin
                overflow <= 1'b0;
                dout <= {32{1'b0}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= significand_r[4][31:0];
            end
        end
        else // positive values
        begin //signal overflow if exponent >= 1054
            invalid_op <= 1'b0;
            if (exp_r[4] >= 1054)
            begin
                overflow <= 1'b1;
                dout <= {1'b0, {31{1'b1}}};
            end
            // round to zero if exponent is 1022 or lower
            else if (exp_r[4] <= 1022)
            begin
                overflow <= 1'b0;
                dout <= {32{1'b0}};
            end
            else
            begin
                overflow <= 1'b0;
                dout <= significand_r[4][31:0];
            end  
        end
      end
    end       

endmodule

module mux4x1 (
    a,
    b,
    c,
    d,
    sel,
    out
    );
    
    parameter DWIDTH = 32;
    
    input [DWIDTH-1:0] a, b, c, d;
    input [1:0] sel;
    output reg [DWIDTH-1:0] out;
    
    always @(*)
    begin
        case(sel)
            2'b00: out = a;
            2'b01: out = b;
            2'b10: out = c;
            2'b11: out = d;
        endcase
    end
endmodule
         