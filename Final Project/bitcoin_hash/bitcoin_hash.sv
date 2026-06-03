module bitcoin_hash (
    input  logic clk, reset_n, start,
    input  logic [15:0] message_addr, output_addr,
    output logic done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input  logic [31:0] mem_read_data
);

    parameter num_nonces = 16;
    
    // Bind memory clock [cite: 732]
    assign mem_clk = clk;

    // Standard SHA-256 Initial Constants [cite: 351, 729-731]
    localparam logic [31:0] H_INIT [0:7] = '{
        32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 
        32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19
    };

    // FSM States
    typedef enum logic [3:0] {
        IDLE,
        READ_MEM,
        PH1_START,       PH1_WAIT,
        PH2_PASS1_START, PH2_PASS1_WAIT,
        PH3_PASS1_START, PH3_PASS1_WAIT,
        PH2_PASS2_START, PH2_PASS2_WAIT,
        PH3_PASS2_START, PH3_PASS2_WAIT,
        WRITE_OUT,
        DONE_ST
    } state_t;

    state_t state;

    // Registers to hold data across FSM steps
    logic [4:0]  read_cnt;
    logic [4:0]  write_cnt;
    logic [31:0] msg_reg [0:18];       // Stores the 19-word block header [cite: 424]
    logic [31:0] H_ph1 [0:7];          // Intermediate Hash from Phase 1 [cite: 355]
    logic [31:0] H_ph2 [0:7][0:7];     // Intermediate Hashes from Phase 2 (8 parallel)
    logic [31:0] H0_final [0:15];      // Final H0 hashes for all 16 nonces [cite: 375, 444]

    // Interfaces for the 8 instantiated SHA256 modules
    logic [31:0] sha_block_in [0:7][0:15];
    logic [31:0] sha_H_in     [0:7][0:7];
    logic [31:0] sha_H_out    [0:7][0:7];
    logic        sha_start    [0:7];
    logic        sha_done     [0:7];

    // Instantiate exactly 8 SHA256 units to fit within FPGA limits 
    genvar i;
    generate
        for (i = 0; i < 8; i++) begin : sha_gen
            sha256 sha_inst (
                .clk(clk),
                .reset_n(reset_n),
                .start(sha_start[i]),
                .block_in(sha_block_in[i]),
                .H_in(sha_H_in[i]),
                .H_out(sha_H_out[i]),
                .done(sha_done[i])
            );
        end
    endgenerate

    // Combinational routing block: Handles input mapping for the 8 SHA256 instances 
    always_comb begin
        // Default assignments to prevent inferred latches
        for (int j = 0; j < 8; j++) begin
            sha_start[j] = 1'b0;
            for (int k = 0; k < 16; k++) sha_block_in[j][k] = 32'd0;
            for (int k = 0; k < 8; k++)  sha_H_in[j][k]     = H_INIT[k];
        end

        case (state)
            PH1_START: begin
                // Phase 1 executes only once because it doesn't contain a nonce [cite: 386]
                sha_start[0] = 1'b1;
                for (int k = 0; k < 16; k++) sha_block_in[0][k] = msg_reg[k];
                for (int k = 0; k < 8; k++)  sha_H_in[0][k]     = H_INIT[k];
            end
            
            PH2_PASS1_START, PH2_PASS2_START: begin
                // Phase 2: Compute 2nd block of 1st hash for 8 nonces concurrently [cite: 354, 390]
                for (int j = 0; j < 8; j++) begin
                    sha_start[j]       = 1'b1;
                    sha_block_in[j][0] = msg_reg[16];
                    sha_block_in[j][1] = msg_reg[17];
                    sha_block_in[j][2] = msg_reg[18];
                    // Map Nonces 0-7 for Pass 1, and 8-15 for Pass 2
                    sha_block_in[j][3] = (state == PH2_PASS1_START) ? 32'(j) : 32'(j + 8); 
                    sha_block_in[j][4] = 32'h8000_0000; // Padding
                    for (int k = 5; k < 15; k++) sha_block_in[j][k] = 32'd0;
                    sha_block_in[j][15] = 32'd640;      // Length padding [cite: 356]
                    for (int k = 0; k < 8; k++)  sha_H_in[j][k] = H_ph1[k]; // Carried over from Phase 1 [cite: 355]
                end
            end
            
            PH3_PASS1_START, PH3_PASS2_START: begin
                // Phase 3: Compute final hash. 8 instances concurrently [cite: 358]
                for (int j = 0; j < 8; j++) begin
                    sha_start[j]       = 1'b1;
                    for (int k = 0; k < 8; k++) sha_block_in[j][k] = H_ph2[j][k]; // Output of Phase 2
                    sha_block_in[j][8] = 32'h8000_0000;
                    for (int k = 9; k < 15; k++) sha_block_in[j][k] = 32'd0;
                    sha_block_in[j][15] = 32'd256;      // Length padding [cite: 360]
                    for (int k = 0; k < 8; k++)  sha_H_in[j][k] = H_INIT[k]; // Reset to initial constants [cite: 359]
                end
            end
            
            default: ; 
        endcase
    end

    // Sequential Block FSM utilizing non-blocking assignments 
    always_ff @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            state          <= IDLE;
            read_cnt       <= '0;
            write_cnt      <= '0;
            done           <= 1'b0;
            mem_we         <= 1'b0;
            mem_addr       <= 16'd0;
            mem_write_data <= 32'd0;
        end else begin
            case (state)
                IDLE: begin
                    done   <= 1'b0;
                    mem_we <= 1'b0;
                    if (start) begin
                        read_cnt  <= '0;
                        write_cnt <= '0;
                        state     <= READ_MEM;
                    end
                end

                READ_MEM: begin
                    // Pipeline read: Request address on cycle N, capture on cycle N+1 [cite: 778, 779]
                    if (read_cnt < 19) begin
                        mem_addr <= message_addr + 16'(read_cnt);
                    end
                    if (read_cnt >= 2) begin
                        msg_reg[read_cnt - 2] <= mem_read_data;
                    end

                    if (read_cnt == 20) begin
                        state <= PH1_START;
                    end else begin
                        read_cnt <= read_cnt + 1;
                    end
                end

                // --- PHASE 1 (Single Execution) ---
                PH1_START: state <= PH1_WAIT;
                
                PH1_WAIT: begin
                    if (sha_done[0]) begin
                        for (int j = 0; j < 8; j++) H_ph1[j] <= sha_H_out[0][j];
                        state <= PH2_PASS1_START;
                    end
                end

                // --- FIRST PASS (Nonces 0-7) ---
                PH2_PASS1_START: state <= PH2_PASS1_WAIT;
                
                PH2_PASS1_WAIT: begin
                    if (sha_done[0]) begin
                        for (int j = 0; j < 8; j++) begin
                            for (int k = 0; k < 8; k++) H_ph2[j][k] <= sha_H_out[j][k];
                        end
                        state <= PH3_PASS1_START;
                    end
                end

                PH3_PASS1_START: state <= PH3_PASS1_WAIT;
                
                PH3_PASS1_WAIT: begin
                    if (sha_done[0]) begin
                        for (int j = 0; j < 8; j++) H0_final[j] <= sha_H_out[j][0];
                        state <= PH2_PASS2_START;
                    end
                end

                // --- SECOND PASS (Nonces 8-15) ---
                PH2_PASS2_START: state <= PH2_PASS2_WAIT;
                
                PH2_PASS2_WAIT: begin
                    if (sha_done[0]) begin
                        for (int j = 0; j < 8; j++) begin
                            for (int k = 0; k < 8; k++) H_ph2[j][k] <= sha_H_out[j][k];
                        end
                        state <= PH3_PASS2_START;
                    end
                end

                PH3_PASS2_START: state <= PH3_PASS2_WAIT;
                
                PH3_PASS2_WAIT: begin
                    if (sha_done[0]) begin
                        for (int j = 0; j < 8; j++) H0_final[j + 8] <= sha_H_out[j][0];
                        state <= WRITE_OUT;
                    end
                end

                // --- MEMORY WRITE ---
                WRITE_OUT: begin
                    if (write_cnt < 16) begin
                        mem_we         <= 1'b1;
                        mem_addr       <= output_addr + 16'(write_cnt);
                        mem_write_data <= H0_final[write_cnt];
                        write_cnt      <= write_cnt + 1;
                    end else begin
                        mem_we <= 1'b0;
                        state  <= DONE_ST;
                    end
                end

                DONE_ST: begin
                    done  <= 1'b1;
                    state <= IDLE;
                end
                
                default: state <= IDLE;
            endcase
        end
    end
endmodule