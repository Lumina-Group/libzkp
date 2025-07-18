use super::ZkpBackend;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, Proof, ProofOptions,
    Prover, TraceInfo, TransitionConstraintDegree, TraceTable, verify, AcceptableOptions,
    BatchingMethod, Trace, PartitionOptions, StarkDomain, CompositionPolyTrace,
    CompositionPoly, DefaultTraceLde, TracePolyTable, DefaultConstraintEvaluator,
    DefaultConstraintCommitment, ConstraintCompositionCoefficients, AuxRandElements,
};

// Build execution trace for the work function x_{i+1} = x_i^3 + 42.
fn build_trace(start: BaseElement, steps: usize) -> TraceTable<BaseElement> {
    let trace_width = 1;
    let mut trace = TraceTable::new(trace_width, steps);
    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
        },
    );
    trace
}

// Compute result of the work function.
fn compute_result(start: BaseElement, steps: usize) -> BaseElement {
    let mut result = start;
    for _ in 1..steps {
        result = result.exp(3u32.into()) + BaseElement::new(42);
    }
    result
}

// Public inputs are the starting value and the result.
struct PublicInputs {
    start: BaseElement,
    result: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

// AIR definition for the work function.
struct WorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
}

impl Air for WorkAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(1, trace_info.width());
        let degrees = vec![TransitionConstraintDegree::new(3)];
        WorkAir {
            context: AirContext::new(trace_info, degrees, 2, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField> + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next_expected = current.exp(3u32.into()) + E::from(42u32);
        result[0] = frame.next()[0] - next_expected;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
        ]
    }
}

// Prover implementing the work AIR.
struct WorkProver {
    options: ProofOptions,
}

impl WorkProver {
    fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for WorkProver {
    type BaseField = BaseElement;
    type Air = WorkAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type VC = MerkleTree<Self::HashFn>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct StarkBackend;

impl ZkpBackend for StarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            return vec![];
        }
        let start = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let steps = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
        let start_el = BaseElement::new(start as u128);
        let prover = WorkProver::new(ProofOptions::new(
            32,
            8,
            0,
            FieldExtension::None,
            8,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        ));
        let trace = build_trace(start_el, steps);
        let proof = prover.prove(trace).expect("failed to prove");
        proof.to_bytes()
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        if data.len() != 16 {
            return false;
        }
        let start = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let steps = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
        let start_el = BaseElement::new(start as u128);
        let result = compute_result(start_el, steps);
        let proof = match Proof::from_bytes(proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pub_inputs = PublicInputs { start: start_el, result };
        let opts = AcceptableOptions::MinConjecturedSecurity(95);
        verify::<WorkAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(proof, pub_inputs, &opts).is_ok()
    }
}
