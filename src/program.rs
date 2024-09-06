use std::collections::{BTreeMap, BTreeSet};

use acvm::acir::{acir_field::GenericFieldElement, circuit::Circuit as ACVMCircuit};
use ark_ff::PrimeField as ArkPrimeField;
use ff::PrimeField;
use ivc_program::{
    program::{get_curve_name, IOProfile, IVCProgram, R1CSConstraint, Term, WitnessID, LC},
    witness::Witness,
    Step,
};
use serde::{Deserialize, Serialize};

use crate::{gate::AcirArithGate, Error};

#[derive(Clone, Serialize, Deserialize)]
pub struct CircuitStructure<F> {
    pub gates: Vec<AcirArithGate<F>>,

    // Note: num of witness and constraints in the program are unused
    pub program: IVCProgram<F>,
}

pub(crate) fn extract_io<AF: ArkPrimeField>(
    acvm_circuit: &ACVMCircuit<GenericFieldElement<AF>>,
    private_outputs: &BTreeSet<WitnessID>,
) -> IOProfile {
    let public_outputs: BTreeSet<WitnessID> = acvm_circuit
        .return_values
        .0
        .iter()
        .map(|x| x.0.into())
        .collect();

    {
        assert!(public_outputs.is_superset(private_outputs));
    }

    let public_outputs = public_outputs
        .difference(private_outputs)
        .cloned()
        .collect();

    let public_inputs = {
        let io: BTreeSet<WitnessID> = acvm_circuit
            .public_inputs()
            .0
            .iter()
            .map(|x| x.0.into())
            .collect();
        io.difference(&public_outputs).cloned().collect()
    };

    let private_inputs = {
        let all_witness: BTreeSet<WitnessID> = acvm_circuit
            .circuit_arguments()
            .iter()
            .map(|x| x.0.into())
            .collect();
        let tmp: BTreeSet<WitnessID> = all_witness.difference(&public_outputs).cloned().collect();
        tmp.difference(&public_inputs).cloned().collect()
    };

    IOProfile {
        public_inputs,
        private_inputs,
        public_outputs,
        private_outputs: private_outputs.clone(),
    }
}

impl<F: PrimeField, AF: ArkPrimeField> From<ACVMCircuit<GenericFieldElement<AF>>>
    for CircuitStructure<F>
{
    fn from(acvm_circuit: ACVMCircuit<GenericFieldElement<AF>>) -> Self {
        let gates = acvm_circuit
            .opcodes
            .iter()
            .cloned()
            .map(|x| x.into())
            .collect();

        let io = extract_io(&acvm_circuit, &Default::default());

        let curve = get_curve_name::<F>();

        let program = IVCProgram {
            io,
            num_witness: 0,
            r1cs_constraints: Default::default(),
            curve,
            version: ivc_program::program::VERSION_0_1.to_string(),
        };

        Self { gates, program }
    }
}

impl<F: PrimeField> CircuitStructure<F> {
    pub fn make_trivial_witness(&self) -> Witness<F> {
        let mut witness_set = BTreeSet::new();

        witness_set.extend(self.program.public_inputs.iter().cloned());
        witness_set.extend(self.program.private_inputs.iter().cloned());
        witness_set.extend(self.program.public_outputs.iter().cloned());
        witness_set.extend(self.program.private_outputs.iter().cloned());

        for gate in &self.gates {
            for (_, left, right) in &gate.mul_terms {
                witness_set.insert(*left);
                witness_set.insert(*right);
            }

            for (_, id) in &gate.add_terms {
                witness_set.insert(*id);
            }
        }

        assert_eq!(
            witness_set.iter().max().unwrap().0,
            witness_set.len() as u32 - 1
        );

        Witness(witness_set.into_iter().map(|id| (id, F::ZERO)).collect())
    }

    pub fn is_valid_input(&self, public_inputs: &Witness<F>, private_inputs: &Witness<F>) -> bool {
        let public_inputs_set_1: BTreeSet<WitnessID> = public_inputs.keys().cloned().collect();
        let private_inputs_set_1: BTreeSet<WitnessID> = private_inputs.keys().cloned().collect();

        let public_inputs_set_2: BTreeSet<WitnessID> =
            self.program.public_inputs.iter().cloned().collect();
        let private_inputs_set_2: BTreeSet<WitnessID> =
            self.program.private_inputs.iter().cloned().collect();

        public_inputs_set_1 == public_inputs_set_2 || private_inputs_set_1 == private_inputs_set_2
    }

    pub fn compile(&self) -> Result<IVCProgram<F>, Error> {
        let solved_witness = self.make_trivial_witness();
        let step = self.make_step(&solved_witness)?;
        Ok(step.program)
    }

    pub fn make_step(&self, solved_witness: &Witness<F>) -> Result<Step<F>, Error> {
        let mut witness: BTreeMap<_, _> = solved_witness
            .iter()
            .map(|(&k, &v)| (WitnessID(k.0), v))
            .collect();

        let mut num_witness = witness.len() as u32;
        let mut r1cs_constraints = Vec::new();

        self.gates.iter().for_each(|gate| {
            let mut big_lc_a = LC::default();

            for (coeff, left, right) in &gate.mul_terms {
                let left_id = WitnessID(left.0);
                let right_id = WitnessID(right.0);

                // todo: return error
                let left_val = *witness.get(&left_id).expect("left not found");
                let right_val = *witness.get(&right_id).expect("right not found");

                let prod_val = left_val * right_val;
                let prod_id = num_witness.into();
                num_witness += 1;

                witness.insert(prod_id, prod_val);

                {
                    let a = LC(vec![Term::LC {
                        coefficient: left_val,
                        var_id: left_id,
                    }]);
                    let b = LC(vec![Term::LC {
                        coefficient: right_val,
                        var_id: right_id,
                    }]);
                    let c = LC(vec![Term::LC {
                        coefficient: prod_val,
                        var_id: prod_id,
                    }]);

                    let constraint = R1CSConstraint { a, b, c };
                    r1cs_constraints.push(constraint);
                }

                big_lc_a.0.push(Term::LC {
                    coefficient: *coeff,
                    var_id: prod_id,
                });
            }

            for (coeff, id) in &gate.add_terms {
                let id = WitnessID(id.0);

                big_lc_a.0.push(Term::LC {
                    coefficient: *coeff,
                    var_id: id,
                });
            }

            big_lc_a.0.push(Term::Const(gate.constant_term));

            {
                let a = big_lc_a;
                let b = LC(vec![Term::Const(F::ONE)]);
                let c = Default::default();
                let constraint = R1CSConstraint { a, b, c };

                r1cs_constraints.push(constraint);
            }
        });

        let ivc_program = IVCProgram {
            io: self.program.io.clone(),
            num_witness,
            r1cs_constraints,
            curve: self.program.curve.clone(),
            version: self.program.version.clone(),
        };

        Ok(Step {
            witness: Witness(witness),
            program: ivc_program,
        })
    }
}
