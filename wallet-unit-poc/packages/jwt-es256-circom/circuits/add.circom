pragma circom 2.1.6;


template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

template Add() {
    signal input a;
    signal input b;

    signal output c;

    component isZeroA = IsZero();
    isZeroA.in <== a;
    isZeroA.out === 0;

    component isZeroB = IsZero();
    isZeroB.in <== b;
    isZeroB.out === 0;

    // component temp = ECDSA();
    
    // temp.s_inverse <== 64526919850504872827331989254453690499656494828399532017685386886700960191042;
    // temp.r <== 61196525693604755845125222333697066101071233796495476903893641112245333701362;
    // temp.m <== 114017827902444732941968516457770191328077153182358580218716007125209722578503;
    // temp.pubKeyX <== 78061130058167562383719608454519460474861159614684608229493268772358316902851;
    // temp.pubKeyY <== 69850379768993415947865882205054119528315212024477847104558401784785143477154;
}