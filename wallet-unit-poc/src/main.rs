//! examples/sha256.rs
//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for a SHA-256
//! circuit with varying message lengths
//!
//! Run with: `RUST_LOG=info cargo run --release --example sha256`
#![allow(non_snake_case)]
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize};
use ff::{PrimeField, PrimeFieldBits};
use spartan2::{
    R1CSSNARK,
    provider::T256HyraxEngine,
    traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use std::{env::current_dir, fs::File, io::Read, path::PathBuf, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

// mod sha256;

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

#[derive(Debug, Clone)]
struct JWTCircuit;

impl SpartanCircuit<E> for JWTCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let root = current_dir().unwrap().join("packages/jwt-es256-circom");
        let witness_dir = root.join("build/add/add_js");
        let wtns = witness_dir.join("main.wasm");
        let r1cs = witness_dir.join("add.r1cs");

        let witness_input_json: String = {
            let path = current_dir()
                .unwrap()
                .join("packages/jwt-es256-circom/inputs/add/default.json");

            let mut file = File::open(path).unwrap();
            let mut witness_input = String::new();
            file.read_to_string(&mut witness_input).unwrap();

            witness_input
        };

        let witness: Vec<_> = generate_witness_from_wasm(
            witness_dir,
            witness_input_json,
            PathBuf::from("output.wtns"),
        );

        let cfg = CircomConfig::new(wtns, r1cs).unwrap();

        synthesize(cs, cfg.r1cs.clone(), Some(witness))?;

        Ok(())
    }

    fn public_values(
        &self,
    ) -> Result<Vec<<E as spartan2::traits::Engine>::Scalar>, SynthesisError> {
        Ok(vec![])
    }

    fn shared<CS: ConstraintSystem<<E as spartan2::traits::Engine>::Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<
        Vec<bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>>,
        SynthesisError,
    > {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<<E as spartan2::traits::Engine>::Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>],
    ) -> Result<
        Vec<bellpepper_core::num::AllocatedNum<<E as spartan2::traits::Engine>::Scalar>>,
        SynthesisError,
    > {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true) // no bold colour codes
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let circuit = JWTCircuit;

    // SETUP
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "setup");

    // PROVE
    let t0 = Instant::now();
    let proof = R1CSSNARK::<E>::prove(&pk, circuit.clone(), true).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "prove");

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "verify");
}
