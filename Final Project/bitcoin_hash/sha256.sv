module sha256 (
    input  logic        clk,
    input  logic        reset_n,
    input  logic        start,
    input  logic [31:0] block_in [0:15], // 512-bit message block
    input  logic [31:0] H_in [0:7],      // Initial hash values (H0-H7)
    output logic [31:0] H_out [0:7],     // Final computed hash values
    output logic        done
);

    // FSM state variables 
    typedef enum logic [1:0] {IDLE, COMPUTE} state_t;
    state_t state;

    // Local variables
    logic [31:0] w[16];
    logic [31:0] h_reg [0:7]; // Registers to hold the incoming H_in for final accumulation
    logic [31:0] a, b, c, d, e, f, g, h;
    logic [6:0]  i;           // Round counter

    // SHA256 K constants
    parameter int k[0:63] = '{
       32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
       32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
       32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
       32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
       32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
       32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
       32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
       32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
    };

    // Right rotation function
    function logic [31:0] rightrotate(input logic [31:0] x, input logic [7:0] r);
        rightrotate = (x >> r) | (x << (32 - r));
    endfunction

    // SHA256 hash round
    function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, input logic [7:0] t);
        logic [31:0] S1, S0, ch, maj, t1, t2; 
        begin
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            ch = (e & f) ^ ((~e) & g);
            t1 = h + S1 + ch + k[t] + w;
            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = S0 + maj;
            sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
        end
    endfunction

    // Word expansion function for the sliding window
    function logic [31:0] wtnew();
        logic [31:0] s0, s1;
        s0 = rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1] >> 3);
        s1 = rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10);
        wtnew = w[0] + s0 + w[9] + s1;
    endfunction

    // SHA-256 Computational Engine FSM
    always_ff @(posedge clk, negedge reset_n) begin
        if (!reset_n) begin
            state <= IDLE;
            done  <= 1'b0;
            i     <= '0;
        end else begin
            case (state)
                IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        // Capture initial hash states for final accumulation
                        h_reg[0] <= H_in[0]; h_reg[1] <= H_in[1]; 
                        h_reg[2] <= H_in[2]; h_reg[3] <= H_in[3];
                        h_reg[4] <= H_in[4]; h_reg[5] <= H_in[5]; 
                        h_reg[6] <= H_in[6]; h_reg[7] <= H_in[7];

                        // Load initial working variables
                        a <= H_in[0]; b <= H_in[1]; c <= H_in[2]; d <= H_in[3];
                        e <= H_in[4]; f <= H_in[5]; g <= H_in[6]; h <= H_in[7];

                        // Load the incoming 16-word block
                        for (int k = 0; k < 16; k++) w[k] <= block_in[k];

                        i     <= 0;
                        state <= COMPUTE;
                    end
                end

                COMPUTE: begin
                    // 64 processing rounds
                    if (i < 64) begin
                        if (i < 15) begin
                            // Rounds 0-14: Use w[i] directly, do not shift window yet
                            {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
                        end else begin
                            // Rounds 15-63: Compute hash and slide the 16-word window
                            {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i);
                            
                            w[0]  <= w[1];  w[1]  <= w[2];  w[2]  <= w[3];
                            w[3]  <= w[4];  w[4]  <= w[5];  w[5]  <= w[6];
                            w[6]  <= w[7];  w[7]  <= w[8];  w[8]  <= w[9];
                            w[9]  <= w[10]; w[10] <= w[11]; w[11] <= w[12];
                            w[12] <= w[13]; w[13] <= w[14]; w[14] <= w[15];
                            w[15] <= wtnew();
                        end
                        i <= i + 1;
                    end else begin
                        // Accumulate final hash values and signal completion
                        H_out[0] <= h_reg[0] + a;
                        H_out[1] <= h_reg[1] + b;
                        H_out[2] <= h_reg[2] + c;
                        H_out[3] <= h_reg[3] + d;
                        H_out[4] <= h_reg[4] + e;
                        H_out[5] <= h_reg[5] + f;
                        H_out[6] <= h_reg[6] + g;
                        H_out[7] <= h_reg[7] + h;

                        done  <= 1'b1;
                        state <= IDLE;
                    end
                end
                
                default: state <= IDLE;
            endcase
        end
    end

endmodule