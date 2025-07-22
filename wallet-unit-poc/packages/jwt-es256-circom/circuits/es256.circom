pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/hash.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/base64.circom";
include "ecdsa/ecdsa.circom";

template ES256(
    n,
    k,
    maxMessageLength
) {
    signal input message[maxMessageLength];
    signal input messageLength; 

    signal input sig_r;
    signal input sig_s_inverse;
    signal input pubKeyX;
    signal input pubKeyY;

    signal output sha[256];

    // Assert message length fits in ceil(log2(maxMessageLength))
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Calculate SHA256 hash of the message
    sha <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // FIXME: This fails if message hash is greater than the scalar field order
    // We should take message hash mod q, since it is an element of the scalar field
    component message_hash_mod_p = Bits2Num(256);
    for (var i = 0; i < 256; i++) message_hash_mod_p.in[i] <== sha[255 - i];

    // Verify the signature
    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== message_hash_mod_p.out;
    ecdsa.pubKeyX <== pubKeyX;
    ecdsa.pubKeyY <== pubKeyY;
}
