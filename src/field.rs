use std::any::type_name;

use crate::{
    constants::{CURVE_BN254, CURVE_BN254_ARK},
    Error,
};
use acvm::{acir::acir_field::GenericFieldElement, AcirField};
use ark_ff::PrimeField as ArkPrimeField;
use ff::PrimeField as PF;
use num::Num;

pub fn assert_types<A: ArkPrimeField, B: PF>() {
    let a = type_name::<A>();
    let b = type_name::<B>();

    assert_eq!(a, CURVE_BN254_ARK);
    assert_eq!(b, CURVE_BN254);
}

pub fn generic_ark_ff_to_prime_field<IF: ArkPrimeField, OF: PF>(
    input: &GenericFieldElement<IF>,
) -> Result<OF, Error> {
    assert_types::<IF, OF>();

    if input.is_zero() {
        return Ok(OF::from(0));
    }

    let text = format!("{}", input.into_repr());

    OF::from_str_vartime(&text).ok_or(Error::FieldConversionError(text))
}

pub fn ff_to_ark_prime_field<IF: PF, OF: ArkPrimeField>(input: &IF) -> Result<OF, Error> {
    assert_types::<OF, IF>();

    if input.is_zero().into() {
        return Ok(OF::zero());
    }

    let bn = {
        let text = format!("{:?}", input);
        let text = text.split_at(2).1;
        num::BigInt::from_str_radix(text, 16).unwrap()
    };

    let text = format!("{}", bn);

    OF::from_str(&text).map_err(|_| Error::FieldConversionError(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ark_to_ff_bn254() {
        type AF = ark_bn254::Fr;
        type F = halo2curves::bn256::Fr;

        let check = |a: AF, b: F| {
            let f = GenericFieldElement::from_repr(a);
            let res: F = generic_ark_ff_to_prime_field(&f).unwrap();

            assert_eq!(res, b);
        };

        check(AF::from(0), F::zero());
        check(AF::from(1), F::one());
        check(AF::from(16), F::one().double().double().double().double());
        check(AF::from(-1), F::zero() - F::one());
    }

    #[test]
    fn test_ff_to_ark_bn254() {
        type AF = ark_bn254::Fr;
        type F = halo2curves::bn256::Fr;

        let check = |a: F, b: AF| {
            let res: AF = ff_to_ark_prime_field(&a).unwrap();

            assert_eq!(res, b);
        };

        check(F::from(0), AF::from(0));
        check(F::from(1), AF::from(1));
        check(F::from(16), AF::from(16));
        check(F::zero() - F::one(), AF::from(-1));
    }
}
