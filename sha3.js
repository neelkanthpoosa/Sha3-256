/**
 * Generates SHA-3 / Keccak hash of message.
 * input    -   {string} message - Message
 * output   -   {string} Hash as hex-encoded string.
 */
function Sha3_256(message) {

    //rate - Bit rate 'r'
    //capacity - Capacity 'c' (b−r), md length × 2
    const rate = 1088, capacity = 512
    
    const length = capacity / 2; // message digest output length in bits

    let msg = null;

    msg = encodetoUTF8(message);
    

    /**
     * Keccak state is a 5 × 5 x w array of bits.
     * State is implemented as a 5 × 5 array of BigInt. 
     * A lane is defined by two planes x, y
     **/
    const state = [ [], [], [], [], [] ];
    for (let x=0; x<5; x++) {
        for (let y=0; y<5; y++) {
            state[x][y] = 0n;
        }
    }

    // append padding
    const q = (rate/8) - msg.length % (rate/8);

    if (q == 1) {
        msg += String.fromCharCode(0x86);
    } else {
        msg += String.fromCharCode(0x06);
        msg += String.fromCharCode(0x00).repeat(q-2);
        msg += String.fromCharCode(0x80);
    }

    // absorbing phase: work through input message in blocks of r bits (r/64 longs, r/8 bytes)

    const w = 64; // w bits in a lane of state
    const blocksize = rate / w * 8; // block size in bytes 

    for (let i=0; i<msg.length; i+=blocksize) {
        for (let j=0; j<rate/w; j++) {
            const i64 = (BigInt(msg.charCodeAt(i+j*8+0))<< 0n) + (BigInt(msg.charCodeAt(i+j*8+1))<< 8n)
                        + (BigInt(msg.charCodeAt(i+j*8+2))<<16n) + (BigInt(msg.charCodeAt(i+j*8+3))<<24n)
                        + (BigInt(msg.charCodeAt(i+j*8+4))<<32n) + (BigInt(msg.charCodeAt(i+j*8+5))<<40n)
                        + (BigInt(msg.charCodeAt(i+j*8+6))<<48n) + (BigInt(msg.charCodeAt(i+j*8+7))<<56n);
            const x = j % 5;
            const y = Math.floor(j / 5);
            state[x][y] = state[x][y] ^ i64;
        }
        keccak_f_permutations(state);
    }

    // squeezing phase: message digest in the first l bits of the state

    // Reverse hex string of each index of a transposed state matrix
    // Join all the hex strings and slice upto required length l
    let md = transpose(state)
        .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0').match(/.{2}/g).reverse().join('')).join(''))
        .join('')
        .slice(0, length/4);

    
    return md;


    function transpose(array) { // to transpose array from  M x N => N x M
        return array.map((row, r) => array.map(col => col[r]));
    }

    function encodetoUTF8(str) {
        try {
            return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { 
            return unescape(encodeURIComponent(str)); 
        }
    }
}

function ROT(a, d) { // 64-bit rotate left
    return BigInt.asUintN(64, a << BigInt(d) | a >> BigInt(64-d));
}

/**
 * Applying permutation Keccak-f[1600] to state a.
 *
 * input    - 5 x 5 array   -   State a
 *
 */
function keccak_f_permutations(a) {

    const permutationRounds = 24; // number of rounds nᵣ = 12 + 2ℓ, hence 24 for Keccak-f[1600] [Keccak §1.2]

    /**
     * Round constants: output of a maximum-length linear feedback shift register (LFSR)
     *
     *   RC[iᵣ][0][0][2ʲ−1] = rc[j+7iᵣ] for 0 ≤ j ≤ l
     * where
     *   rc[t] = ( xᵗ mod x⁸ + x⁶ + x⁵ + x⁴ + 1 ) mod x in GF(2)[x].
     */
    const RC = [
        0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
        0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
        0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
        0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
        0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
        0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
        0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
        0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
    ];

    // Keccak-f permutations
    for (let r=0; r<permutationRounds; r++) {
        // applying step mappings θ, ρ, π, χ, ι to the state 'a'

        // θ step method
        const C = [], D = []; // intermediate sub-states
        for (let x=0; x<5; x++) {
            C[x] = a[x][0];
            for (let y=1; y<5; y++) {
                C[x] = C[x] ^ a[x][y];
            }
        }
        for (let x=0; x<5; x++) {
            // D[x] = C[x−1] XOR ROT(C[x+1], 1)
            D[x] = C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);
            // a[x,y] = a[x,y] XOR D[x]
            for (let y=0; y<5; y++) {
                a[x][y] = a[x][y] ^ D[x];
            }
        }

        // ρ + π step methods
        let [ x, y ] = [ 1, 0 ];
        let current = a[x][y];
        for (let t=0; t<24; t++) {
            const [ X, Y ] = [ y, (2*x + 3*y) % 5 ];
            const tmp = a[X][Y];
            a[X][Y] = ROT(current, ((t+1)*(t+2)/2) % 64);
            current = tmp;
            [ x, y ] = [ X, Y ];
        }

        // It should be noted that by folding the π step into the ρ step, 
        // only the current lane needs to be cached; 
        // looping around x and y would need taking a copy of the entire π step.
        // state for the A[X,Y] = a[x,y] operation

        // χ step method
        for (let y=0; y<5; y++) {
            const C = [];  // take a copy of the plane
            for (let x=0; x<5; x++) C[x] = a[x][y];
            for (let x=0; x<5; x++) {
                a[x][y] = (C[x] ^ ((~C[(x+1)%5]) & C[(x+2)%5]));
            }
        }

        // ι step method
        a[0][0] = (a[0][0] ^ RC[r]);
    }

    


    



}

