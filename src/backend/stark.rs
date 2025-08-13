use super::ZkpBackend;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, Prover, TraceInfo,
    TraceTable, TransitionConstraintDegree, Trace,
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    DefaultTraceLde, DefaultConstraintEvaluator, TracePolyTable,
    StarkDomain, ConstraintCompositionCoefficients, AuxRandElements,
    Proof, AcceptableOptions, PartitionOptions,
};
use winter_utils::Serializable;

// Define the AIR (Algebraic Intermediate Representation) for our proof system
struct ImprovementAir {
    context: AirContext<BaseElement>,
    old_value: BaseElement,
    new_value: BaseElement,
    step_size: BaseElement,
}

// Wrapper for public inputs to implement ToElements
#[derive(Clone, Debug)]
struct PublicInputs(Vec<BaseElement>);

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.0.clone()
    }
}

impl Air for ImprovementAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(pub_inputs.0.len(), 2);
        let degrees = vec![TransitionConstraintDegree::new(1)];
        
        let old_value = pub_inputs.0[0];
        let new_value = pub_inputs.0[1];
        let trace_length = trace_info.length();
        
        // Calculate step size for linear interpolation
        let diff = new_value - old_value;
        let steps = BaseElement::new((trace_length - 1) as u128);
        let step_size = diff / steps;
        
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
            old_value,
            new_value,
            step_size,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];
        
        // Constraint: next = current + step_size
        // This ensures linear interpolation from old to new value
        let step_size = E::from(self.step_size);
        result[0] = next - current - step_size;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(0, 0, self.old_value),
            Assertion::single(0, self.trace_length() - 1, self.new_value),
        ]
    }
}

// Prover implementation
struct ImprovementProver {
    options: ProofOptions,
}

impl ImprovementProver {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                32,     // number of queries
                8,      // blowup factor
                0,      // grinding factor
                winterfell::FieldExtension::None,
                8,      // FRI folding factor
                31,     // FRI max remainder degree
            ),
        }
    }
}

impl Prover for ImprovementProver {
    type BaseField = BaseElement;
    type Air = ImprovementAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> = DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let old_value = trace.get(0, 0);
        let new_value = trace.get(0, trace.length() - 1);
        PublicInputs(vec![old_value, new_value])
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField> + From<Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField> + From<Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct StarkBackend;

impl StarkBackend {
    fn prove_improvement(old: u64, new: u64) -> Result<Vec<u8>, String> {
        if new <= old {
            return Err("new value must be greater than old value".to_string());
        }

        // Create the trace showing progression from old to new value
        let trace_length = 8; // Use a small power of 2 for efficiency
        let mut trace = TraceTable::new(1, trace_length);
        
        // Calculate step size
        let old_elem = BaseElement::new(old as u128);
        let new_elem = BaseElement::new(new as u128);
        let diff = new_elem - old_elem;
        let steps = BaseElement::new((trace_length - 1) as u128);
        let step_size = diff / steps;
        
        // Generate trace with exact linear interpolation
        let mut current = old_elem;
        for i in 0..trace_length {
            trace.set(0, i, current);
            if i < trace_length - 1 {
                current = current + step_size;
            }
        }

        // Build the proof
        let prover = ImprovementProver::new();
        let proof = prover.prove(trace).map_err(|e| format!("proof generation failed: {:?}", e))?;
        
        // Serialize the proof
        let mut bytes = Vec::new();
        proof.write_into(&mut bytes);
        Ok(bytes)
    }

    fn verify_improvement(proof_data: &[u8], old: u64, new: u64) -> Result<bool, String> {
        // Deserialize the proof
        let proof = Proof::from_bytes(proof_data)
            .map_err(|e| format!("failed to deserialize proof: {:?}", e))?;
        
        // Prepare public inputs
        let pub_inputs = PublicInputs(vec![
            BaseElement::new(old as u128),
            BaseElement::new(new as u128),
        ]);
        
        // Create acceptable options for verification
        let acceptable_options = AcceptableOptions::OptionSet(vec![ImprovementProver::new().options().clone()]);
        
        // Verify the proof
        winterfell::verify::<ImprovementAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
            proof, 
            pub_inputs,
            &acceptable_options
        )
        .map(|_| true)
        .map_err(|e| format!("verification failed: {:?}", e))
    }
}

impl ZkpBackend for StarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            return vec![];
        }
        
        let old = match data[0..8].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return vec![],
        };
        let new = match data[8..16].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return vec![],
        };
        
        match Self::prove_improvement(old, new) {
            Ok(proof) => proof,
            Err(_) => vec![],
        }
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        if data.len() != 16 {
            return false;
        }
        
        let old = match data[0..8].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return false,
        };
        let new = match data[8..16].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return false,
        };
        
        Self::verify_improvement(proof, old, new).unwrap_or(false)
    }
}
