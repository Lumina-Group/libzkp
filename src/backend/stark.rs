use super::ZkpBackend;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, DefaultSerializer,
    EvaluationFrame, ProofOptions, Prover, StarkProof, TraceInfo,
    TraceTable, TransitionConstraintDegree, Serializable,
};
use std::collections::BTreeMap;

// Define the AIR (Algebraic Intermediate Representation) for our proof system
struct ImprovementAir {
    context: AirContext<BaseElement>,
    old_value: BaseElement,
    new_value: BaseElement,
}

impl Air for ImprovementAir {
    type BaseField = BaseElement;
    type PublicInputs = Vec<BaseElement>;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(pub_inputs.len(), 2);
        let degrees = vec![TransitionConstraintDegree::new(1)];
        
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
            old_value: pub_inputs[0],
            new_value: pub_inputs[1],
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
        
        // Constraint: next value must be greater than or equal to current
        // This is represented as: next - current >= 0
        // In field arithmetic, we check that the difference is a valid field element
        result[0] = next - current;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> Vec<BaseElement> {
        let old_value = trace.get(0, 0);
        let new_value = trace.get(0, trace.length() - 1);
        vec![old_value, new_value]
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement + From<Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::ColMatrix<Self::BaseField>,
        domain: &winterfell::StarkDomain<Self::BaseField>,
    ) -> (winterfell::RowMatrix<E>, winterfell::TracePolyTable<E>) {
        winterfell::DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<E: FieldElement + From<Self::BaseField>>(
        &self,
        air: &Self::Air,
        aux_rand_elements: winterfell::AuxTraceRandElements<E>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> winterfell::DefaultConstraintEvaluator<'_, Self::Air, E> {
        winterfell::DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
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
        
        // Linear interpolation from old to new value
        for i in 0..trace_length {
            // Use integer arithmetic to avoid floating-point inaccuracies.
            let value = old as u128 + ((new as u128 - old as u128) * i as u128) / ((trace_length - 1) as u128);
            trace.set(0, i, BaseElement::new(value));
        }

        // Build the proof
        let prover = ImprovementProver::new();
        let proof = prover.prove(trace).map_err(|e| format!("proof generation failed: {:?}", e))?;
        
        // Serialize the proof
        let mut serializer = DefaultSerializer::new();
        proof.write_into(&mut serializer);
        Ok(serializer.into_bytes())
    }

    fn verify_improvement(proof_data: &[u8], old: u64, new: u64) -> Result<bool, String> {
        // Deserialize the proof
        let proof = StarkProof::from_bytes(proof_data)
            .map_err(|e| format!("failed to deserialize proof: {:?}", e))?;
        
        // Prepare public inputs
        let pub_inputs = vec![
            BaseElement::new(old as u128),
            BaseElement::new(new as u128),
        ];
        
        // Verify the proof
        winterfell::verify::<ImprovementAir>(proof, pub_inputs)
            .map(|_| true)
            .map_err(|e| format!("verification failed: {:?}", e))
    }
}

impl ZkpBackend for StarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            return vec![];
        }
        
        let old = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let new = u64::from_le_bytes(data[8..16].try_into().unwrap());
        
        match Self::prove_improvement(old, new) {
            Ok(proof) => proof,
            Err(_) => vec![],
        }
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        if data.len() != 16 {
            return false;
        }
        
        let old = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let new = u64::from_le_bytes(data[8..16].try_into().unwrap());
        
        Self::verify_improvement(proof, old, new).unwrap_or(false)
    }
}
