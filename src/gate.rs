use acvm::acir::{acir_field::GenericFieldElement, circuit::Opcode, native_types::Expression};
use ark_ff::PrimeField as ArkPrimeField;
use ff::PrimeField;
use ivc_program::program::WitnessID;
use serde::{Deserialize, Serialize};

use crate::field::{ff_to_ark_prime_field, generic_ark_ff_to_prime_field};

// adapted from arkworks_backend::bridge::AcirArithGate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcirArithGate<F> {
    pub mul_terms: Vec<(F, WitnessID, WitnessID)>,
    pub add_terms: Vec<(F, WitnessID)>,
    pub constant_term: F,
}

impl<AF: ArkPrimeField, F: PrimeField> From<AcirArithGate<F>> for Opcode<GenericFieldElement<AF>> {
    fn from(source: AcirArithGate<F>) -> Self {
        let mut_terms = source
            .mul_terms
            .into_iter()
            .map(|(c, l, r)| {
                let c = ff_to_ark_prime_field(&c).expect("mul terms conversion error");
                let l = l.0.into();
                let r = r.0.into();
                (GenericFieldElement::from_repr(c), l, r)
            })
            .collect();

        let add_terms = source
            .add_terms
            .into_iter()
            .map(|(c, w)| {
                let c = ff_to_ark_prime_field(&c).expect("add terms conversion error");
                let w = w.0.into();
                (GenericFieldElement::from_repr(c), w)
            })
            .collect();

        let constant_term = GenericFieldElement::from_repr(
            ff_to_ark_prime_field(&source.constant_term).expect("constant term conversion error"),
        );

        Opcode::AssertZero(Expression {
            mul_terms: mut_terms,
            linear_combinations: add_terms,
            q_c: constant_term,
        })
    }
}

impl<AF, F> From<Opcode<GenericFieldElement<AF>>> for AcirArithGate<F>
where
    AF: ArkPrimeField,
    F: PrimeField,
{
    fn from(opcode: Opcode<GenericFieldElement<AF>>) -> Self {
        if let Opcode::AssertZero(op) = opcode {
            let mul_terms = op
                .mul_terms
                .into_iter()
                .map(|(c, l, r)| {
                    (
                        generic_ark_ff_to_prime_field(&c).expect("mul terms conversion error"),
                        l.0.into(),
                        r.0.into(),
                    )
                })
                .collect();
            let add_terms = op
                .linear_combinations
                .into_iter()
                .map(|(c, w)| {
                    (
                        generic_ark_ff_to_prime_field(&c).expect("add terms conversion error"),
                        w.0.into(),
                    )
                })
                .collect();
            let constant_term =
                generic_ark_ff_to_prime_field(&op.q_c).expect("constant term conversion error");

            Self {
                mul_terms,
                add_terms,
                constant_term,
            }
        } else {
            panic!("Unsupported opcode");
        }
    }
}
