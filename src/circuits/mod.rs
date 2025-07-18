// Circuit definitions and utilities

pub mod merkle_tree;
pub mod set_membership;
pub mod generic_circuit;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Generic constraint system for ZKP circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSystem {
    pub variables: Vec<Variable>,
    pub constraints: Vec<LinearConstraint>,
    pub public_inputs: Vec<usize>, // Indices into variables
    pub private_inputs: Vec<usize>, // Indices into variables
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub var_type: VariableType,
    pub value: Option<i64>, // For witness generation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    Field,
    Boolean,
    UInt(usize), // bit width
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearConstraint {
    pub a: HashMap<usize, i64>, // variable_index -> coefficient
    pub b: HashMap<usize, i64>, // variable_index -> coefficient  
    pub c: HashMap<usize, i64>, // variable_index -> coefficient
    pub constant: i64,
    // Represents: (sum(a[i] * var[i]) + constant) * (sum(b[i] * var[i])) = sum(c[i] * var[i])
}

impl ConstraintSystem {
    pub fn new() -> Self {
        Self {
            variables: Vec::new(),
            constraints: Vec::new(),
            public_inputs: Vec::new(),
            private_inputs: Vec::new(),
        }
    }
    
    pub fn add_variable(&mut self, name: String, var_type: VariableType) -> usize {
        let index = self.variables.len();
        self.variables.push(Variable {
            name,
            var_type,
            value: None,
        });
        index
    }
    
    pub fn add_public_input(&mut self, var_index: usize) {
        if !self.public_inputs.contains(&var_index) {
            self.public_inputs.push(var_index);
        }
    }
    
    pub fn add_private_input(&mut self, var_index: usize) {
        if !self.private_inputs.contains(&var_index) {
            self.private_inputs.push(var_index);
        }
    }
    
    pub fn add_constraint(&mut self, constraint: LinearConstraint) {
        self.constraints.push(constraint);
    }
    
    /// Add a range constraint: min <= var <= max
    pub fn add_range_constraint(&mut self, var_index: usize, min: i64, max: i64) {
        // This is a simplified representation - actual implementation would
        // decompose this into bit constraints for ZKP systems
        let mut a = HashMap::new();
        a.insert(var_index, 1);
        
        // var >= min constraint: var - min >= 0
        let constraint1 = LinearConstraint {
            a: a.clone(),
            b: HashMap::new(),
            c: HashMap::new(),
            constant: -min,
        };
        
        // var <= max constraint: max - var >= 0
        let mut a2 = HashMap::new();
        a2.insert(var_index, -1);
        let constraint2 = LinearConstraint {
            a: a2,
            b: HashMap::new(),
            c: HashMap::new(),
            constant: max,
        };
        
        self.add_constraint(constraint1);
        self.add_constraint(constraint2);
    }
    
    /// Add an equality constraint: var1 == var2
    pub fn add_equality_constraint(&mut self, var1_index: usize, var2_index: usize) {
        let mut a = HashMap::new();
        a.insert(var1_index, 1);
        a.insert(var2_index, -1);
        
        let constraint = LinearConstraint {
            a,
            b: HashMap::new(),
            c: HashMap::new(),
            constant: 0,
        };
        
        self.add_constraint(constraint);
    }
    
    /// Set witness values for variables
    pub fn set_witness(&mut self, var_index: usize, value: i64) {
        if var_index < self.variables.len() {
            self.variables[var_index].value = Some(value);
        }
    }
    
    /// Check if all constraints are satisfied with current witness
    pub fn check_constraints(&self) -> bool {
        for constraint in &self.constraints {
            if !self.check_single_constraint(constraint) {
                return false;
            }
        }
        true
    }
    
    fn check_single_constraint(&self, constraint: &LinearConstraint) -> bool {
        let a_sum = self.evaluate_linear_combination(&constraint.a) + constraint.constant;
        let b_sum = self.evaluate_linear_combination(&constraint.b);
        let c_sum = self.evaluate_linear_combination(&constraint.c);
        
        // For linear constraints, b is typically empty, so we check a_sum == c_sum
        if constraint.b.is_empty() {
            a_sum == c_sum
        } else {
            // For quadratic constraints: a_sum * b_sum == c_sum
            a_sum * b_sum == c_sum
        }
    }
    
    fn evaluate_linear_combination(&self, coeffs: &HashMap<usize, i64>) -> i64 {
        let mut sum = 0;
        for (&var_index, &coeff) in coeffs {
            if let Some(value) = self.variables.get(var_index).and_then(|v| v.value) {
                sum += coeff * value;
            }
        }
        sum
    }
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Circuit builder for common ZKP patterns
pub struct CircuitBuilder {
    cs: ConstraintSystem,
}

impl CircuitBuilder {
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
        }
    }
    
    /// Build a range proof circuit
    pub fn build_range_circuit(mut self, min: i64, max: i64) -> ConstraintSystem {
        let value_var = self.cs.add_variable("value".to_string(), VariableType::UInt(64));
        self.cs.add_private_input(value_var);
        self.cs.add_range_constraint(value_var, min, max);
        self.cs
    }
    
    /// Build an equality proof circuit
    pub fn build_equality_circuit(mut self) -> ConstraintSystem {
        let value1_var = self.cs.add_variable("value1".to_string(), VariableType::UInt(64));
        let value2_var = self.cs.add_variable("value2".to_string(), VariableType::UInt(64));
        
        self.cs.add_private_input(value1_var);
        self.cs.add_private_input(value2_var);
        self.cs.add_equality_constraint(value1_var, value2_var);
        self.cs
    }
    
    /// Build a threshold proof circuit
    pub fn build_threshold_circuit(mut self, threshold: i64) -> ConstraintSystem {
        let value_var = self.cs.add_variable("value".to_string(), VariableType::UInt(64));
        let threshold_var = self.cs.add_variable("threshold".to_string(), VariableType::UInt(64));
        
        self.cs.add_private_input(value_var);
        self.cs.add_public_input(threshold_var);
        self.cs.set_witness(threshold_var, threshold);
        
        // value >= threshold constraint
        self.cs.add_range_constraint(value_var, threshold, i64::MAX);
        self.cs
    }
    
    pub fn finalize(self) -> ConstraintSystem {
        self.cs
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}