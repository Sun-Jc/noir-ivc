use ivc_program::witness::Witness;
use serde::{Deserialize, Serialize};

pub mod constants {
    pub const CURVE_BN254: &str = "halo2curves::bn256::fr::Fr";
    pub const CURVE_BN254_ARK: &str = "ark_ff::fields::models::fp::Fp<ark_ff::fields::models::fp::montgomery_backend::MontBackend<ark_bn254::fields::fr::FrConfig, 4>, 4>";
    pub const NOIR_VERSION_0_33: &str = "0.33.0+325dac54efb6f99201de9fdeb0a507d45189607d";
}

mod execute;
mod field;
mod gate;
mod load;
mod program;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unsupported program: {0}")]
    UnsupportedProgram(#[from] load::UnsupportedProgramError),

    #[error("Field conversion error {0}")]
    FieldConversionError(String),

    #[error("Invalid input")]
    InvalidInput,

    #[error("IVCProgram error: {0}")]
    IVCProgramError(#[from] ivc_program::Error),

    #[error("ACVM Solving error: {0}")]
    ACVMSolveError(String),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExecutionResult<F> {
    pub iteration_number: u64,
    pub public_input: Witness<F>,
    pub private_input: Witness<F>,
    pub public_output: Witness<F>,
    pub private_output: Witness<F>,
}

pub mod functions {
    use std::path::Path;

    use acvm::acir::{acir_field::GenericFieldElement, circuit::Circuit as ACVMCircuit};
    use ark_ff::PrimeField as ArkPrimeField;
    use arkworks_backend::ProgramArtifactGeneric;
    use ff::PrimeField;
    use ivc_program::{input::IO, program::IVCProgram, witness::Witness};

    use crate::{
        constants::NOIR_VERSION_0_33,
        execute::UnexecutedCircuit,
        load::{check_supported, print_metadata},
        program::CircuitStructure,
        Error, ExecutionResult,
    };

    fn load_circuit<F: ArkPrimeField>(
        program: &[u8],
        print_info: bool,
    ) -> Result<ACVMCircuit<GenericFieldElement<F>>, Error> {
        let noir_program: ProgramArtifactGeneric<F> = serde_json::from_slice(program).unwrap();

        let program = noir_program.bytecode;

        if print_info {
            print_metadata(&program);
        }

        assert_eq!(noir_program.noir_version, NOIR_VERSION_0_33.to_string());

        check_supported(&program)?;

        Ok(program.functions[0].clone())
    }

    /// Load a noir circuit from a file
    /// Adapted from `dmpierre/arkworks_backend`
    pub fn load_circuit_from_file<F: ArkPrimeField, P: AsRef<Path>>(
        circuit_path: P,
        print_info: bool,
    ) -> Result<ACVMCircuit<GenericFieldElement<F>>, Error> {
        let input_string = std::fs::read(&circuit_path).unwrap();

        load_circuit(&input_string, print_info)
    }

    pub fn load_circuit_from_text<F: ArkPrimeField>(
        json_text: &str,
        print_info: bool,
    ) -> Result<ACVMCircuit<GenericFieldElement<F>>, Error> {
        let input_string = json_text.to_string();
        load_circuit(input_string.as_bytes(), print_info)
    }

    /// Compile a noir circuit into
    /// 1. a noir-ivc program
    /// 2. an IVC program
    /// 3. a trivial IVC witness
    #[allow(clippy::type_complexity)]
    pub fn compile<F: PrimeField, AF: ArkPrimeField>(
        noir_circuit: ACVMCircuit<GenericFieldElement<AF>>,
    ) -> Result<(CircuitStructure<F>, IVCProgram<F>), Error> {
        let structure: CircuitStructure<F> = noir_circuit.into();
        let program = structure.compile()?;
        Ok((structure, program))
    }

    pub fn execute_steps<F: PrimeField, AF: ArkPrimeField>(
        circuit: CircuitStructure<F>,
        first_public_input: Witness<F>,
        start_step_num: u64,
        private_inputs: impl Iterator<Item = Witness<F>>,
    ) -> impl Iterator<Item = Result<(ExecutionResult<F>, Witness<F>, IO<F>), Error>> {
        let mut circuit = UnexecutedCircuit::new(start_step_num, first_public_input, circuit);

        private_inputs.map(move |private_input| {
            let (exe_res, witness, next) = circuit.clone().execute::<AF>(private_input)?;

            let next_input = next.public_input.clone().into();

            circuit = next;

            Ok((exe_res, witness, next_input))
        })
    }
}
pub use functions::*;
pub use program::CircuitStructure;
