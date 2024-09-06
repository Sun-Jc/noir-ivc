use acvm::acir::{
    acir_field::GenericFieldElement,
    circuit::{Opcode, Program},
};
use ark_ff::PrimeField as ArkPrimeField;

use crate::program::extract_io;

#[derive(Debug, thiserror::Error)]
pub enum UnsupportedProgramError {
    #[error("Program has more than one function ({0})")]
    MultipleFunctions(usize),
    #[error("Program has unconstrained functions ({0})")]
    UnconstrainedFunctions(usize),
    #[error("Program has an opcode that is not an AssertZero ({0:?})")]
    NonAssertZeroOpcode(String),
    #[error("Malformed program: {0}")]
    MalformedProgram(#[from] ivc_program::program::MalformedProgramError),
}

pub fn print_metadata<F: ArkPrimeField>(program: &Program<GenericFieldElement<F>>) {
    println!("Program Info:");
    println!(
        "  Number of constrained functions: {}",
        program.functions.len()
    );
    println!(
        "  Number of unconstrained functions: {}",
        program.unconstrained_functions.len()
    );

    for (i, func) in program.unconstrained_functions.iter().enumerate() {
        println!("  Unconstrained function {}: {:?}", i, func);
    }

    for (i, circuit) in program.functions.iter().enumerate() {
        println!("  Function {}: {} opcodes", i, circuit.opcodes.len());
        let io = &circuit.public_inputs().0;
        let output = &circuit.return_values.0;
        let all = &circuit.circuit_arguments();

        let input = io - output;
        let private = {
            let tmp = all - output;
            &tmp - &input
        };

        println!("  #IO inputs: {:?}", input.len());
        println!(
            "             [{}]",
            input
                .iter()
                .map(|x| format!("{}", x.0))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  #IO outputs: {:?}", output.len());
        println!(
            "             [{}]",
            output
                .iter()
                .map(|x| format!("{}", x.0))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  #Private inputs: {:?}", private.len());
        println!("  First <20 opcodes:");
        for (i, opcode) in circuit.opcodes.iter().enumerate().take(20) {
            println!("    op{}: {:?}", i, opcode);
        }
    }
}

pub fn check_supported<F: ArkPrimeField>(
    program: &Program<GenericFieldElement<F>>,
) -> Result<(), UnsupportedProgramError> {
    {
        let num_functions = program.functions.len();
        if num_functions != 1 {
            return Err(UnsupportedProgramError::MultipleFunctions(num_functions));
        }
    }

    {
        let num_unconstrained_functions = program.unconstrained_functions.len();
        if num_unconstrained_functions != 0 {
            return Err(UnsupportedProgramError::UnconstrainedFunctions(
                num_unconstrained_functions,
            ));
        }
    }

    let circuit = &program.functions[0];

    for op in &circuit.opcodes {
        if !matches!(op, Opcode::AssertZero(_)) {
            return Err(UnsupportedProgramError::NonAssertZeroOpcode(format!(
                "{:?}",
                op
            )));
        }
    }

    extract_io(circuit, &Default::default()).check_structure()?;

    Ok(())
}
