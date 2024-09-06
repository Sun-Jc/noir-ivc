use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
use ff::PrimeField;
use ivc_program::{input::IO, program::IVCProgram, witness::Witness, Step};
use serde::{de::DeserializeOwned, Serialize};
use std::{fs::File, path::Path};

use crate::{compile, execute_steps, load_circuit_from_file, program::CircuitStructure};

#[inline]
fn read<T: DeserializeOwned>(path: &str) -> T {
    let path = std::env::current_dir()
        .unwrap()
        .join(path)
        .to_str()
        .unwrap()
        .to_string();
    serde_json::from_reader(File::open(path).unwrap()).unwrap()
}

#[inline]
fn write<T: Serialize>(path: &str, data: &T) {
    let path = std::env::current_dir()
        .unwrap()
        .join(path)
        .to_str()
        .unwrap()
        .to_string();
    std::fs::create_dir_all(Path::new(&path).parent().unwrap()).unwrap();
    serde_json::to_writer(File::create(path).unwrap(), data).unwrap();
}

type F = halo2curves::bn256::Fr;
type AF = ark_bn254::Fr;

const NOIR_PROGRAM_PATH: &str = "test_folder/invert/target/invert.json";
const NOIR_IVC_PROGRAM_PATH: &str = "test_folder/invert/target/noir-ivc/noir_ivc_program.json";
const IVC_PROGRAM_PATH: &str = "test_folder/invert/target/noir-ivc/ivc_program.json";
const INPUT_PATHS: [&str; 3] = [
    "test_folder/invert/inputs/io_0.json",
    "test_folder/invert/target/noir-ivc/io_1.json",
    "test_folder/invert/target/noir-ivc/io_2.json",
];
const HINT_PATHS: [&str; 2] = [
    "test_folder/invert/inputs/hint_0.json",
    "test_folder/invert/inputs/hint_1.json",
];
const WITNESS_PATHS: [&str; 2] = [
    "test_folder/invert/target/noir-ivc/step_0.wit",
    "test_folder/invert/target/noir-ivc/step_1.wit",
];
const EXECUTION_RES_PATHS: [&str; 2] = [
    "test_folder/invert/target/noir-ivc/step_0.res",
    "test_folder/invert/target/noir-ivc/step_1.res",
];

#[test]
fn test_compile_and_execute() {
    // 1. compile
    {
        let noir_circuit = load_circuit_from_file::<AF, _>(NOIR_PROGRAM_PATH, true).unwrap();

        let (circuit_structure, ivc_program) = compile::<F, AF>(noir_circuit).unwrap();

        write(NOIR_IVC_PROGRAM_PATH, &circuit_structure);

        write(IVC_PROGRAM_PATH, &ivc_program);
    }

    // 2. execute
    let circuit: CircuitStructure<F> = read(NOIR_IVC_PROGRAM_PATH);
    let io_profile = circuit.program.io.clone();
    execute_steps::<F, AF>(
        circuit,
        {
            let input: IO<u128> = read(INPUT_PATHS[0]);
            let input: Vec<F> = input.0.iter().map(|x| F::from_u128(*x)).collect();
            let input: IO<F> = input.into();
            input.make_witness(&io_profile)
        },
        0,
        HINT_PATHS.into_iter().map(|path| {
            let input: IO<String> = read(path);
            let input = IO(input
                .0
                .iter()
                .map(|x| F::from_str_vartime(x).unwrap())
                .collect());
            input.make_witness(&io_profile)
        }),
    )
    .enumerate()
    .for_each(|(step_num, res)| {
        let (res, wit, io) = res.unwrap();

        let io = io.make_witness(&io_profile);
        write(INPUT_PATHS[step_num + 1], &io);

        write(WITNESS_PATHS[step_num], &wit);
        write(EXECUTION_RES_PATHS[step_num], &res);
    });
}

#[test]
fn test_compile_execute_cs() {
    test_compile_and_execute();

    let witness_0: Witness<F> = read(WITNESS_PATHS[0]);
    let witness_1: Witness<F> = read(WITNESS_PATHS[1]);

    let program: IVCProgram<F> = read(IVC_PROGRAM_PATH);
    {
        let step0 = Step {
            witness: witness_0,
            program: program.clone(),
        };

        let mut cs = TestConstraintSystem::<F>::new();
        step0.prove(cs.namespace(|| "prove")).unwrap();
        assert!(cs.is_satisfied());
    }

    {
        let step1 = Step {
            witness: witness_1,
            program: program.clone(),
        };

        let mut cs = TestConstraintSystem::<F>::new();
        step1.prove(cs.namespace(|| "prove")).unwrap();
        assert!(cs.is_satisfied());
    }
}
