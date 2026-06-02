module bitcoin_hash (
    input  logic        clk, reset_n, start,
    input  logic [15:0] message_addr, output_addr,
    output logic        done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input  logic [31:0] mem_read_data
);

    parameter num_nonces = 16;

    // Fixed constant arrays provided
    parameter int k[64] = '{
        32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
        32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
        32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
        32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
        32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
        32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
        32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
        32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
    };

    // SHA-256 Initial Constants
    localparam logic [31:0] H0_INIT = 32'h6a09e667;
    localparam logic [31:0] H1_INIT = 32'hbb67ae85;
    localparam logic [31:0] H2_INIT = 32'h3c6ef372;
    localparam logic [31:0] H3_INIT = 32'ha54ff53a;
    localparam logic [31:0] H4_INIT = 32'h510e527f;
    localparam logic [31:0] H5_INIT = 32'h9b05688c;
    localparam logic [31:0] H6_INIT = 32'h1f83d9ab;
    localparam logic [31:0] H7_INIT = 32'h5be0cd19;

    // Memory Clock Binding
    assign mem_clk = clk;

    // FSM States
    typedef enum logic [3:0] {
        IDLE,
        READ_MEM,
        PHASE1_INIT,
        COMPRESS1,
        PHASE2_INIT,
        COMPRESS2,
        PHASE3_INIT,
        COMPRESS3,
        WRITE_OUT,
        DONE_ST
    } state_t;

    state_t state, next_state;

    // Datapath Registers
    logic [31:0] msg_reg [0:18], next_msg_reg [0:18];
    logic [4:0]  read_cnt, next_read_cnt;
    logic [6:0]  t, next_t;
    logic [31:0] nonce, next_nonce;

    logic [31:0] H_int [0:7], next_H_int [0:7];
    logic [31:0] H_ph2 [0:7], next_H_ph2 [0:7];
    logic [31:0] W_reg [0:15], next_W_reg [0:15];

    logic [31:0] a, b, c, d, e, f, g, h;
    logic [31:0] next_a, next_b, next_c, next_d, next_e, next_f, next_g, next_h;

    // SHA-256 Helper Functions
    function automatic logic [31:0] ROTR(input logic [31:0] x, input int n);
        return (x >> n) | (x << (32 - n));
    endfunction

    function automatic logic [31:0] Ch(input logic [31:0] x, y, z);
        return (x & y) ^ (~x & z);
    endfunction

    function automatic logic [31:0] Maj(input logic [31:0] x, y, z);
        return (x & y) ^ (x & z) ^ (y & z);
    endfunction

    function automatic logic [31:0] Sigma0(input logic [31:0] x);
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    endfunction

    function automatic logic [31:0] Sigma1(input logic [31:0] x);
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    endfunction

    function automatic logic [31:0] sigma0_small(input logic [31:0] x);
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    endfunction

    function automatic logic [31:0] sigma1_small(input logic [31:0] x);
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    endfunction

    // Sequential Block
    always_ff @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            state    <= IDLE;
            read_cnt <= '0;
            t        <= '0;
            nonce    <= '0;
            a <= '0; b <= '0; c <= '0; d <= '0;
            e <= '0; f <= '0; g <= '0; h <= '0;
            
            for (int i = 0; i < 19; i++) msg_reg[i] <= '0;
            for (int i = 0; i < 8; i++) begin
                H_int[i] <= '0;
                H_ph2[i] <= '0;
            end
            for (int i = 0; i < 16; i++) W_reg[i] <= '0;
        end else begin
            state    <= next_state;
            read_cnt <= next_read_cnt;
            t        <= next_t;
            nonce    <= next_nonce;
            a <= next_a; b <= next_b; c <= next_c; d <= next_d;
            e <= next_e; f <= next_f; g <= next_g; h <= next_h;
            
            for (int i = 0; i < 19; i++) msg_reg[i] <= next_msg_reg[i];
            for (int i = 0; i < 8; i++) begin
                H_int[i] <= next_H_int[i];
                H_ph2[i] <= next_H_ph2[i];
            end
            for (int i = 0; i < 16; i++) W_reg[i] <= next_W_reg[i];
        end
    end

    // Combinational Logic Block
    always_comb begin
        // Default outputs to prevent inferred latches
        next_state    = state;
        next_read_cnt = read_cnt;
        next_t        = t;
        next_nonce    = nonce;
        
        next_a = a; next_b = b; next_c = c; next_d = d;
        next_e = e; next_f = f; next_g = g; next_h = h;

        for (int i = 0; i < 19; i++) next_msg_reg[i] = msg_reg[i];
        for (int i = 0; i < 8; i++) begin
            next_H_int[i] = H_int[i];
            next_H_ph2[i] = H_ph2[i];
        end
        for (int i = 0; i < 16; i++) next_W_reg[i] = W_reg[i];

        mem_addr       = 16'd0;
        mem_write_data = 32'd0;
        mem_we         = 1'b0;
        done           = 1'b0;

        // --- SHA-256 Core Variables ---
        begin : sha256_comb
            logic [31:0] Wt;
            logic [31:0] T1, T2;
            logic [3:0]  w_idx, w_idx_2, w_idx_7, w_idx_15;

            w_idx    = t[3:0]; // Sliding 16-word window index
            w_idx_2  = (t - 2) & 4'hF;
            w_idx_7  = (t - 7) & 4'hF;
            w_idx_15 = (t - 15) & 4'hF;

            // W_t Word Expansion Array calculation
            if (t < 16) begin
                Wt = W_reg[w_idx];
            end else begin
                Wt = sigma1_small(W_reg[w_idx_2]) + W_reg[w_idx_7] + sigma0_small(W_reg[w_idx_15]) + W_reg[w_idx];
            end

            // Compression Formulas
            T1 = h + Sigma1(e) + Ch(e, f, g) + k[t] + Wt;
            T2 = Sigma0(a) + Maj(a, b, c);

            // --- Finite State Machine ---
            case (state)
                IDLE: begin
                    if (start) begin
                        next_read_cnt = 0;
                        next_state    = READ_MEM;
                    end
                end

                READ_MEM: begin
                    // Pipeline read: Address set in cycle N, Data captured in cycle N+1
                    if (read_cnt < 19) mem_addr = message_addr + 16'(read_cnt);
                    if (read_cnt > 0) next_msg_reg[read_cnt - 1] = mem_read_data;

                    if (read_cnt == 19) begin
                        next_state = PHASE1_INIT;
                    end else begin
                        next_read_cnt = read_cnt + 1;
                    end
                end

                PHASE1_INIT: begin
                    next_a = H0_INIT; next_b = H1_INIT; next_c = H2_INIT; next_d = H3_INIT;
                    next_e = H4_INIT; next_f = H5_INIT; next_g = H6_INIT; next_h = H7_INIT;

                    for (int i = 0; i < 16; i++) next_W_reg[i] = msg_reg[i];
                    next_t     = 0;
                    next_state = COMPRESS1;
                end

                COMPRESS1: begin
                    next_h = g; next_g = f; next_f = e; next_e = d + T1;
                    next_d = c; next_c = b; next_b = a; next_a = T1 + T2;
                    
                    next_W_reg[w_idx] = Wt;

                    if (t == 63) begin
                        next_H_int[0] = H0_INIT + next_a;
                        next_H_int[1] = H1_INIT + next_b;
                        next_H_int[2] = H2_INIT + next_c;
                        next_H_int[3] = H3_INIT + next_d;
                        next_H_int[4] = H4_INIT + next_e;
                        next_H_int[5] = H5_INIT + next_f;
                        next_H_int[6] = H6_INIT + next_g;
                        next_H_int[7] = H7_INIT + next_h;
                        
                        next_nonce = 0;
                        next_state = PHASE2_INIT;
                    end else begin
                        next_t = t + 1;
                    end
                end

                PHASE2_INIT: begin
                    next_a = H_int[0]; next_b = H_int[1]; next_c = H_int[2]; next_d = H_int[3];
                    next_e = H_int[4]; next_f = H_int[5]; next_g = H_int[6]; next_h = H_int[7];

                    // Set up 2nd Block with Nonce and Padding
                    next_W_reg[0] = msg_reg[16];
                    next_W_reg[1] = msg_reg[17];
                    next_W_reg[2] = msg_reg[18];
                    next_W_reg[3] = nonce;
                    next_W_reg[4] = 32'h8000_0000;
                    for (int i = 5; i < 15; i++) next_W_reg[i] = 32'd0;
                    next_W_reg[15] = 32'd640;
                    
                    next_t     = 0;
                    next_state = COMPRESS2;
                end

                COMPRESS2: begin
                    next_h = g; next_g = f; next_f = e; next_e = d + T1;
                    next_d = c; next_c = b; next_b = a; next_a = T1 + T2;
                    
                    next_W_reg[w_idx] = Wt;

                    if (t == 63) begin
                        next_H_ph2[0] = H_int[0] + next_a;
                        next_H_ph2[1] = H_int[1] + next_b;
                        next_H_ph2[2] = H_int[2] + next_c;
                        next_H_ph2[3] = H_int[3] + next_d;
                        next_H_ph2[4] = H_int[4] + next_e;
                        next_H_ph2[5] = H_int[5] + next_f;
                        next_H_ph2[6] = H_int[6] + next_g;
                        next_H_ph2[7] = H_int[7] + next_h;

                        next_state = PHASE3_INIT;
                    end else begin
                        next_t = t + 1;
                    end
                end

                PHASE3_INIT: begin
                    next_a = H0_INIT; next_b = H1_INIT; next_c = H2_INIT; next_d = H3_INIT;
                    next_e = H4_INIT; next_f = H5_INIT; next_g = H6_INIT; next_h = H7_INIT;

                    // Set up Final SHA256 Block and Padding
                    for (int i = 0; i < 8; i++) next_W_reg[i] = H_ph2[i];
                    next_W_reg[8] = 32'h8000_0000;
                    for (int i = 9; i < 15; i++) next_W_reg[i] = 32'd0;
                    next_W_reg[15] = 32'd256;
                    
                    next_t     = 0;
                    next_state = COMPRESS3;
                end

                COMPRESS3: begin
                    next_h = g; next_g = f; next_f = e; next_e = d + T1;
                    next_d = c; next_c = b; next_b = a; next_a = T1 + T2;
                    
                    next_W_reg[w_idx] = Wt;

                    if (t == 63) begin
                        next_state = WRITE_OUT;
                    end else begin
                        next_t = t + 1;
                    end
                end

                WRITE_OUT: begin
                    // Store only H0 to output_addr + nonce
                    mem_addr       = output_addr + 16'(nonce);
                    mem_write_data = H0_INIT + a; // Final compression addition
                    mem_we         = 1'b1;
                    
                    if (nonce == num_nonces - 1) begin
                        next_state = DONE_ST;
                    end else begin
                        next_nonce = nonce + 1;
                        next_state = PHASE2_INIT;
                    end
                end

                DONE_ST: begin
                    done       = 1'b1;
                    next_state = IDLE;
                end
                
                default: next_state = IDLE;
            endcase
        end // block: sha256_comb
    end
endmodule