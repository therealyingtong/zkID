//! examples/sha256.rs
//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for a SHA-256
//! circuit with varying message lengths
//!
//! Run with: `RUST_LOG=info cargo run --release --example sha256`
#![allow(non_snake_case)]
use bellpepper_core::{
  Circuit, ConstraintSystem, SynthesisError,
};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize};
use ff::{PrimeField, PrimeFieldBits};
use spartan2::{
  R1CSSNARK,
  provider::T256HyraxEngine,
  traits::snark::R1CSSNARKTrait,
};
use std::{env::current_dir, fs::File, io::Read, path::PathBuf, time::Instant};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

#[derive(Debug, Clone)]
struct JWTCircuit;

impl<Scalar: PrimeField + PrimeFieldBits> Circuit<Scalar> for JWTCircuit {
  fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    let root = current_dir().unwrap();
    let witness_dir = root.join("jwt_js");
    let wtns = witness_dir.join("main.wasm");
    let r1cs = witness_dir.join("jwt.r1cs");

    let witness_input_json: String = {
        let path = current_dir()
            .unwrap()
            .join("packages/jwt-es256-circom/inputs/jwt/default.json");

        let mut file = File::open(path).unwrap();
        let mut witness_input = String::new();
        file.read_to_string(&mut witness_input).unwrap();
        
        witness_input
    };

    let witness = generate_witness_from_wasm(witness_dir, witness_input_json, PathBuf::from("output.wtns"));

    let cfg = CircomConfig::new(wtns, r1cs).unwrap();

    synthesize(
        cs,
        cfg.r1cs.clone(),
        Some(witness),
    )?;

    Ok(())
  }
}

fn main() {
    tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)                // no bold colour codes
    .with_env_filter(EnvFilter::from_default_env())
    .init();

    let circuit = JWTCircuit;

    // SETUP
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    // println!("setup_ms: {}", setup_ms);

    // GENERATE WITNESS
    let t0 = Instant::now();
    let (U, W) =
      R1CSSNARK::<E>::gen_witness(&pk, circuit.clone(), true).expect("gen_witness failed");
    let gw_ms = t0.elapsed().as_millis();

    // println!("gw_ms: {}", gw_ms);

    // PROVE
    let t0 = Instant::now();
    let proof: R1CSSNARK<T256HyraxEngine> = R1CSSNARK::<E>::prove(&pk, &U, &W).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    // println!("prove_ms: {}", prove_ms);

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    // println!("verify_ms: {}", verify_ms);
}
