pragma circom 2.1.2;

include "./add.circom";
include "./double.circom";
// include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

// 

/**
 *  Secp256r1Mul
 *  ============
 *
 *  Implements https://zcash.github.io/halo2/design/gadgets/ecc/var-base-scalar-mul.html
 *  which allows us to use incomplete addition for the majority of the addition steps
 *  and only use complete addition for the final 3 steps.
 *
 *  Modified from https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/secp256k1/mul.circom
 */
template Secp256r1Mul() {
    var bits = 256;
    // A scalar field element fits in the base field
    signal input scalar;
    signal input xP; 
    signal input yP;
    signal output outX;
    signal output outY;

    component kBits = K_add();
    kBits.s <== scalar;

    // component acc0 = Secp256r1Double();
    // acc0.xP <== xP;
    // acc0.yP <== yP;

    // component PIncomplete[bits-3]; 
    // component accIncomplete[bits];

    // for (var i = 0; i < bits-3; i++) {
    //     if (i == 0) {
    //         PIncomplete[i] = Secp256r1AddIncomplete(); // (Acc + P)
    //         PIncomplete[i].xP <== xP; // kBits[i] ? xP : -xP;
    //         PIncomplete[i].yP <== -yP;// kBits[i] ? xP : -xP;
    //         PIncomplete[i].xQ <== acc0.outX;
    //         PIncomplete[i].yQ <== acc0.outY;
            

    //         accIncomplete[i] = Secp256r1AddIncomplete(); // (Acc + P) + Acc
    //         accIncomplete[i].xP <== acc0.outX;
    //         accIncomplete[i].yP <== acc0.outY;
    //         accIncomplete[i].xQ <== PIncomplete[i].outX;
    //         accIncomplete[i].yQ <== PIncomplete[i].outY;
    //     } else {
    //         PIncomplete[i] = Secp256r1AddIncomplete(); // (Acc + P)
    //         PIncomplete[i].xP <== xP; // k_i ? xP : -xP;
    //         PIncomplete[i].yP <== (2 * kBits.out[bits-i] - 1) * yP;// k_i ? xP : -xP;
    //         PIncomplete[i].xQ <== accIncomplete[i-1].outX;
    //         PIncomplete[i].yQ <== accIncomplete[i-1].outY;

    //         accIncomplete[i] = Secp256r1AddIncomplete(); // (Acc + P) + Acc
    //         accIncomplete[i].xP <== accIncomplete[i-1].outX;
    //         accIncomplete[i].yP <== accIncomplete[i-1].outY;
    //         accIncomplete[i].xQ <== PIncomplete[i].outX;
    //         accIncomplete[i].yQ <== PIncomplete[i].outY;
    //     }
    // }

    // component PComplete[bits-3]; 
    // component accComplete[3];

    // for (var i = 0; i < 3; i++) {
    //     PComplete[i] = Secp256r1AddComplete(); // (Acc + P)

    //     PComplete[i].xP <== xP; // k_i ? xP : -xP;
    //     PComplete[i].yP <== (2 * kBits.out[3 - i] - 1) * yP;// k_i ? xP : -xP;
    //     if (i == 0) {
    //         PComplete[i].xQ <== accIncomplete[252].outX;
    //         PComplete[i].yQ <== accIncomplete[252].outY;
    //     } else {
    //         PComplete[i].xQ <== accComplete[i-1].outX;
    //         PComplete[i].yQ <== accComplete[i-1].outY;
    //     }

    //     accComplete[i] = Secp256r1AddComplete(); // (Acc + P) + Acc
    //     if (i == 0) {
    //         accComplete[i].xP <== accIncomplete[252].outX;
    //         accComplete[i].yP <== accIncomplete[252].outY;
    //     } else {
    //         accComplete[i].xP <== accComplete[i-1].outX;
    //         accComplete[i].yP <== accComplete[i-1].outY;
    //     }

    //     accComplete[i].xQ <== PComplete[i].outX;
    //     accComplete[i].yQ <== PComplete[i].outY;
    // }

    // component out = Secp256r1AddComplete();
    // out.xP <== accComplete[2].outX;
    // out.yP <== accComplete[2].outY;
    // out.xQ <== (1 - kBits.out[0]) * xP;
    // out.yQ <== (1 - kBits.out[0]) * -yP;

    // outX <== out.outX;
    // outY <== out.outY;
}


template Num2Bits2(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }
    
    log(in);
    log(lc1);
    lc1 === in;
}

// Calculate k = (s + tQ) % q as follows:
// Define notation: (s + tQ) / q = (quotient, remainder)
// We can calculate the quotient and remainder as:
// (s + tQ) < q ? = (0, s - tQ) : (1, (s - tQ) - q)
// We use 128-bit registers to calculate the above since (s + tQ) can be larger than p.
template K_add() {
    var bits = 256;
    signal input s;
    signal output out[bits];

    // Split elements into 128 bit registers

    var q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551; // The order of the scalar field
    var qlo = q & ((2 ** 128) - 1);
    var qhi = q >> 128;
    var tQ = 115792089183396302101823908890127239206723925782630956645386934114223894448802; // (q - 2^256) % q;
    var tQlo = tQ & (2 ** (128) - 1);
    
    var tQhi = tQ >> 128;
    signal slo <-- s & (2 ** (128) - 1);
    signal shi <-- s >> 128;


    // // // Get carry bit of (slo + tQlo)

    component inBits = Num2Bits2(128 + 1);
    inBits.in <== slo + tQlo;
    signal carry <== inBits.out[128];

    // check a >= b
    // where
    // a = (s + tQ)
    // b = q

    // - alpha: ahi > bhi
    // - beta: ahi = bhi
    // - gamma: alo ≥ blo
    // if alpha or (beta and gamma) then a >= b
    
    // signal ahi <== shi + tQhi + carry;
    // signal bhi <== qhi;
    // signal alo <== slo + tQlo - (carry * 2 ** 128);
    // signal blo <== qlo;

    // component alpha = GreaterThan(129);
    // alpha.in[0] <-- ahi;
    // alpha.in[1] <-- bhi;

    // component beta = IsEqual();
    // beta.in[0] <== ahi;
    // beta.in[1] <== bhi;

    // component gamma = GreaterEqThan(129);
    // gamma.in[0] <== alo;
    // gamma.in[1] <== blo;

    // component betaANDgamma = AND();
    // betaANDgamma.a <== beta.out;
    // betaANDgamma.b <== gamma.out;

    // component isQuotientOne = OR();
    // isQuotientOne.a <== betaANDgamma.out;
    // isQuotientOne.b <== alpha.out;

    // // theta: (slo + tQlo) < qlo
    // component theta = GreaterThan(129);
    // theta.in[0] <== qlo;
    // theta.in[1] <== slo + tQlo;

    // // borrow: (slo + tQlo) < qlo and isQuotientOne ? 1 : 0
    // component borrow = AND();
    // borrow.a <== theta.out;
    // borrow.b <== isQuotientOne.out;

    // signal klo <== (slo + tQlo + borrow.out * (2 ** 128)) - isQuotientOne.out * qlo;
    // signal khi <== (shi + tQhi - borrow.out * 1)  - isQuotientOne.out * qhi;

    // component kloBits = Num2Bits(256);
    // kloBits.in <== klo;

    // component khiBits = Num2Bits(256);
    // khiBits.in <== khi;

    // for (var i = 0; i < 128; i++) {
    //     out[i] <== kloBits.out[i];
    //     out[i + 128] <== khiBits.out[i];
    // }


// out[0]  <== 0;
// out[1]  <== 1;
// out[2]  <== 0;
// out[3]  <== 1;
// out[4]  <== 0;
// out[5]  <== 0;
// out[6]  <== 0;
// out[7]  <== 1;
// out[8]  <== 0;
// out[9]  <== 1;
// out[10] <== 1;
// out[11] <== 0;
// out[12] <== 1;
// out[13] <== 0;
// out[14] <== 1;
// out[15] <== 0;
// out[16] <== 0;
// out[17] <== 1;
// out[18] <== 0;
// out[19] <== 1;
// out[20] <== 0;
// out[21] <== 1;
// out[22] <== 0;
// out[23] <== 0;
// out[24] <== 1;
// out[25] <== 1;
// out[26] <== 0;
// out[27] <== 1;
// out[28] <== 0;
// out[29] <== 0;
// out[30] <== 1;
// out[31] <== 1;
// out[32] <== 0;
// out[33] <== 1;
// out[34] <== 1;
// out[35] <== 1;
// out[36] <== 1;
// out[37] <== 1;
// out[38] <== 1;
// out[39] <== 0;
// out[40] <== 0;
// out[41] <== 1;
// out[42] <== 0;
// out[43] <== 1;
// out[44] <== 1;
// out[45] <== 0;
// out[46] <== 0;
// out[47] <== 0;
// out[48] <== 0;
// out[49] <== 1;
// out[50] <== 0;
// out[51] <== 0;
// out[52] <== 0;
// out[53] <== 0;
// out[54] <== 1;
// out[55] <== 1;
// out[56] <== 1;
// out[57] <== 0;
// out[58] <== 1;
// out[59] <== 0;
// out[60] <== 1;
// out[61] <== 1;
// out[62] <== 0;
// out[63] <== 1;
// out[64] <== 0;
// out[65] <== 0;
// out[66] <== 0;
// out[67] <== 0;
// out[68] <== 0;
// out[69] <== 0;
// out[70] <== 0;
// out[71] <== 1;
// out[72] <== 1;
// out[73] <== 1;
// out[74] <== 0;
// out[75] <== 0;
// out[76] <== 0;
// out[77] <== 0;
// out[78] <== 1;
// out[79] <== 1;
// out[80] <== 0;
// out[81] <== 0;
// out[82] <== 1;
// out[83] <== 0;
// out[84] <== 0;
// out[85] <== 0;
// out[86] <== 1;
// out[87] <== 1;
// out[88] <== 0;
// out[89] <== 1;
// out[90] <== 0;
// out[91] <== 1;
// out[92] <== 0;
// out[93] <== 0;
// out[94] <== 1;
// out[95] <== 0;
// out[96] <== 0;
// out[97] <== 0;
// out[98] <== 1;
// out[99] <== 0;
// out[100]<== 1;
// out[101]<== 0;
// out[102]<== 1;
// out[103]<== 1;
// out[104]<== 1;
// out[105]<== 0;
// out[106]<== 1;
// out[107]<== 1;
// out[108]<== 0;
// out[109]<== 0;
// out[110]<== 1;
// out[111]<== 1;
// out[112]<== 1;
// out[113]<== 0;
// out[114]<== 1;
// out[115]<== 0;
// out[116]<== 0;
// out[117]<== 0;
// out[118]<== 1;
// out[119]<== 0;
// out[120]<== 0;
// out[121]<== 0;
// out[122]<== 1;
// out[123]<== 1;
// out[124]<== 0;
// out[125]<== 0;
// out[126]<== 0;
// out[127]<== 0;
// out[128]<== 1;
// out[129]<== 1;
// out[130]<== 0;
// out[131]<== 0;
// out[132]<== 1;
// out[133]<== 0;
// out[134]<== 0;
// out[135]<== 0;
// out[136]<== 1;
// out[137]<== 0;
// out[138]<== 1;
// out[139]<== 1;
// out[140]<== 1;
// out[141]<== 0;
// out[142]<== 0;
// out[143]<== 0;
// out[144]<== 0;
// out[145]<== 0;
// out[146]<== 0;
// out[147]<== 1;
// out[148]<== 1;
// out[149]<== 1;
// out[150]<== 0;
// out[151]<== 1;
// out[152]<== 1;
// out[153]<== 1;
// out[154]<== 1;
// out[155]<== 1;
// out[156]<== 1;
// out[157]<== 1;
// out[158]<== 1;
// out[159]<== 0;
// out[160]<== 0;
// out[161]<== 1;
// out[162]<== 1;
// out[163]<== 0;
// out[164]<== 0;
// out[165]<== 0;
// out[166]<== 0;
// out[167]<== 0;
// out[168]<== 1;
// out[169]<== 0;
// out[170]<== 0;
// out[171]<== 0;
// out[172]<== 1;
// out[173]<== 0;
// out[174]<== 0;
// out[175]<== 0;
// out[176]<== 1;
// out[177]<== 0;
// out[178]<== 0;
// out[179]<== 1;
// out[180]<== 0;
// out[181]<== 0;
// out[182]<== 0;
// out[183]<== 0;
// out[184]<== 1;
// out[185]<== 1;
// out[186]<== 1;
// out[187]<== 1;
// out[188]<== 1;
// out[189]<== 0;
// out[190]<== 1;
// out[191]<== 1;
// out[192]<== 1;
// out[193]<== 0;
// out[194]<== 1;
// out[195]<== 0;
// out[196]<== 0;
// out[197]<== 0;
// out[198]<== 0;
// out[199]<== 0;
// out[200]<== 0;
// out[201]<== 0;
// out[202]<== 1;
// out[203]<== 0;
// out[204]<== 1;
// out[205]<== 1;
// out[206]<== 1;
// out[207]<== 0;
// out[208]<== 1;
// out[209]<== 1;
// out[210]<== 0;
// out[211]<== 0;
// out[212]<== 1;
// out[213]<== 1;
// out[214]<== 1;
// out[215]<== 1;
// out[216]<== 0;
// out[217]<== 0;
// out[218]<== 0;
// out[219]<== 0;
// out[220]<== 1;
// out[221]<== 0;
// out[222]<== 0;
// out[223]<== 0;
// out[224]<== 0;
// out[225]<== 0;
// out[226]<== 1;
// out[227]<== 0;
// out[228]<== 1;
// out[229]<== 0;
// out[230]<== 1;
// out[231]<== 0;
// out[232]<== 1;
// out[233]<== 0;
// out[234]<== 1;
// out[235]<== 1;
// out[236]<== 0;
// out[237]<== 1;
// out[238]<== 1;
// out[239]<== 1;
// out[240]<== 0;
// out[241]<== 0;
// out[242]<== 0;
// out[243]<== 0;
// out[244]<== 1;
// out[245]<== 1;
// out[246]<== 1;
// out[247]<== 0;
// out[248]<== 0;
// out[249]<== 1;
// out[250]<== 1;
// out[251]<== 1;
// out[252]<== 1;
// out[253]<== 1;
// out[254]<== 0;
// out[255]<== 1;

}