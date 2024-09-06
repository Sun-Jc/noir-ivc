use std::collections::BTreeMap;

use acvm::{
    acir::{acir_field::GenericFieldElement, circuit::Opcode, native_types::WitnessMap},
    blackbox_solver::StubbedBlackBoxSolver,
    pwg::{ACVMStatus, ACVM},
};
use ark_ff::PrimeField as ArkPrimeField;
use ff::PrimeField;
use ivc_program::{program::WitnessID, witness::Witness};

use crate::{
    field::{ff_to_ark_prime_field, generic_ark_ff_to_prime_field},
    program::CircuitStructure,
    Error, ExecutionResult,
};

#[derive(Clone)]
pub struct UnexecutedCircuit<F> {
    pub iteration_number: u64,
    pub public_input: Witness<F>,
    pub structure: CircuitStructure<F>,
}

impl<F> UnexecutedCircuit<F> {
    pub fn new(
        iteration_number: u64,
        init_public_input: Witness<F>,
        structure: CircuitStructure<F>,
    ) -> Self {
        Self {
            iteration_number,
            public_input: init_public_input,
            structure,
        }
    }
}

impl<F: PrimeField> UnexecutedCircuit<F> {
    pub fn execute<AF: ArkPrimeField>(
        self,
        private_input: Witness<F>,
    ) -> Result<(ExecutionResult<F>, Witness<F>, Self), Error> {
        assert!(self
            .structure
            .is_valid_input(&self.public_input, &private_input));

        // merge public and private input into one
        let mut assigned_witness = self.public_input.clone();
        assigned_witness.0.extend(private_input.0);

        let initial_witness: Result<_, Error> = assigned_witness
            .iter()
            .map(|(witness_id, value)| {
                let value: AF = ff_to_ark_prime_field(value)?;
                let id = acvm::acir::native_types::Witness(witness_id.0);

                Ok((id, GenericFieldElement::from_repr(value)))
            })
            .collect();

        let initial_witness: BTreeMap<acvm::acir::native_types::Witness, GenericFieldElement<AF>> =
            initial_witness?;

        let initial_witness = WitnessMap::from(initial_witness);

        // Todo: cache
        let opcodes: Vec<Opcode<GenericFieldElement<AF>>> = self
            .structure
            .gates
            .iter()
            .cloned()
            .map(|gate| gate.into())
            .collect::<Vec<_>>();

        let mut acvm = ACVM::new(&StubbedBlackBoxSolver, &opcodes, initial_witness, &[], &[]);

        let status = acvm.solve();
        match status {
            ACVMStatus::Solved => Ok(()),
            _ => Err(Error::ACVMSolveError(format!("{:?}", status))),
        }?;

        let solved_witness = acvm.finalize();

        let solved_witness: BTreeMap<WitnessID, F> = solved_witness
            .into_iter()
            .map(|(witness, value)| {
                let value = generic_ark_ff_to_prime_field(&value).expect("output fill error");
                (witness.0.into(), value)
            })
            .collect();

        let solved_witness = Witness(solved_witness);

        let public_input = solved_witness.extract_subset(&self.structure.program.public_inputs)?;
        let private_input =
            solved_witness.extract_subset(&self.structure.program.private_inputs)?;
        let public_output =
            solved_witness.extract_subset(&self.structure.program.public_outputs)?;
        let private_output =
            solved_witness.extract_subset(&self.structure.program.private_outputs)?;

        let result = ExecutionResult {
            iteration_number: self.iteration_number,
            public_input: public_input.clone(),
            private_input,
            public_output: public_output.clone(),
            private_output,
        };

        let step = self.structure.make_step(&solved_witness)?;

        let new_public_input = public_output.make_next_input_witness(&self.structure.program.io);

        let next = Self {
            iteration_number: self.iteration_number + 1,
            public_input: new_public_input,
            structure: self.structure,
        };

        Ok((result, step.witness, next))
    }
}
