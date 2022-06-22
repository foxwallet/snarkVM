// Copyright (C) 2019-2022 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

mod circuit_value;
pub(crate) use circuit_value::*;

mod stack_value;
pub use stack_value::*;

mod load;
mod store;

use crate::{Operand, Program, RegisterTypes};
use console::{
    network::prelude::*,
    program::{Ciphertext, Entry, Identifier, Literal, Plaintext, Record, Register, Value, ValueType},
};

use indexmap::IndexMap;

pub struct Stack<N: Network, A: circuit::Aleo<Network = N>> {
    /// The program (record types, interfaces, functions).
    program: Program<N, A>,
    /// The mapping of all registers to their defined types.
    register_types: RegisterTypes<N>,
    /// The mapping of assigned console registers to their values.
    console_registers: IndexMap<u64, StackValue<N>>,
    /// The mapping of assigned circuit registers to their values.
    circuit_registers: IndexMap<u64, CircuitValue<A>>,
}

impl<N: Network, A: circuit::Aleo<Network = N>> Stack<N, A> {
    /// Initializes a new stack, given the program and register types.
    #[inline]
    pub fn new(program: Program<N, A>, register_types: RegisterTypes<N>) -> Result<Self> {
        Ok(Self { program, register_types, console_registers: IndexMap::new(), circuit_registers: IndexMap::new() })
    }

    /// Returns the program.
    #[inline]
    pub const fn program(&self) -> &Program<N, A> {
        &self.program
    }

    /// Evaluates a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    pub fn evaluate(
        program: Program<N, A>,
        function_name: &Identifier<N>,
        inputs: &[StackValue<N>],
    ) -> Result<Vec<Value<N, Plaintext<N>>>> {
        // Retrieve the function from the program.
        let function = program.get_function(function_name)?;
        // Ensure the number of inputs matches the number of input statements.
        if function.inputs().len() != inputs.len() {
            bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
        }

        // Retrieve the register types.
        let register_types = program.get_function_registers(function_name)?;
        // Initialize the stack.
        let mut stack = Self::new(program, register_types.clone())?;

        // Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            stack.store(&register, input.clone())
        })?;

        // Evaluate the instructions.
        function.instructions().iter().try_for_each(|instruction| instruction.evaluate(&mut stack))?;

        // Load the outputs.
        let outputs = function.outputs().iter().map(|output| {
            // Retrieve the stack value from the register.
            let stack_value = stack.load(&Operand::Register(output.register().clone()))?;
            // Convert the stack value to the output value type.
            let output = match (stack_value, output.value_type()) {
                (StackValue::Plaintext(plaintext), ValueType::Constant(..)) => Value::Constant(plaintext),
                (StackValue::Plaintext(plaintext), ValueType::Public(..)) => Value::Public(plaintext),
                (StackValue::Plaintext(plaintext), ValueType::Private(..)) => Value::Private(plaintext),
                (StackValue::Record(record), ValueType::Record(..)) => Value::Record(record),
                _ => bail!("Stack value does not match the expected output type"),
            };
            // Return the output.
            Ok(output)
        });

        outputs.collect()
    }

    /// Executes a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    pub fn execute(
        program: Program<N, A>,
        function_name: &Identifier<N>,
        inputs: &[StackValue<N>],
    ) -> Result<Vec<circuit::Value<A, circuit::Plaintext<A>>>> {
        // Retrieve the function from the program.
        let function = program.get_function(function_name)?;
        // Ensure the number of inputs matches the number of input statements.
        if function.inputs().len() != inputs.len() {
            bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
        }

        // Retrieve the register types for the function.
        let register_types = program.get_function_registers(function_name)?;
        // Initialize the stack.
        let mut stack = Self::new(program, register_types)?;

        // Store the inputs.
        function.inputs().iter().map(|i| (i.register(), i.value_type())).zip_eq(inputs).try_for_each(
            |((register, value_type), input)| {
                // Assign the console input to the register.
                stack.store(&register, input.clone())?;
                // Assign the circuit input to the register.
                stack.store_circuit(&register, match value_type {
                    ValueType::Constant(..) => circuit::Inject::new(circuit::Mode::Constant, input.clone()),
                    ValueType::Public(..) => circuit::Inject::new(circuit::Mode::Public, input.clone()),
                    ValueType::Private(..) => circuit::Inject::new(circuit::Mode::Private, input.clone()),
                    ValueType::Record(..) => circuit::Inject::new(circuit::Mode::Private, input.clone()),
                })
            },
        )?;

        // Execute the instructions.
        function.instructions().iter().try_for_each(|instruction| instruction.evaluate(&mut stack))?;
        function.instructions().iter().try_for_each(|instruction| instruction.execute(&mut stack))?;

        // Load the outputs.
        let outputs = function.outputs().iter().map(|output| {
            // Retrieve the circuit output from the register.
            let circuit_output = stack.load_circuit(&Operand::Register(output.register().clone()))?;
            // Construct the circuit output value.
            let output = match (circuit_output, output.value_type()) {
                (CircuitValue::Plaintext(plaintext), ValueType::Constant(..)) => circuit::Value::Constant(plaintext),
                (CircuitValue::Plaintext(plaintext), ValueType::Public(..)) => circuit::Value::Public(plaintext),
                (CircuitValue::Plaintext(plaintext), ValueType::Private(..)) => circuit::Value::Private(plaintext),
                (CircuitValue::Record(record), ValueType::Record(..)) => circuit::Value::Record(record),
                _ => bail!("Circuit value does not match the expected output type"),
            };
            // Return the output.
            Ok(output)
        });

        outputs.collect()
    }

    /// Executes a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    pub fn execute_transition(
        program: Program<N, A>,
        function_name: &Identifier<N>,
        inputs: &[CircuitValue<A>],
    ) -> Result<Vec<circuit::Value<A, circuit::Plaintext<A>>>> {
        // Retrieve the function from the program.
        let function = program.get_function(function_name)?;
        // Ensure the number of inputs matches the number of input statements.
        if function.inputs().len() != inputs.len() {
            bail!("Expected {} inputs, found {}", function.inputs().len(), inputs.len())
        }

        // Retrieve the register types for the function.
        let register_types = program.get_function_registers(function_name)?;
        // Initialize the stack.
        let mut stack = Self::new(program, register_types)?;

        // Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            use circuit::Eject;

            // Assign the console input to the register.
            stack.store(&register, input.eject_value())?;
            // Assign the circuit input to the register.
            stack.store_circuit(&register, input.clone())
        })?;

        // Execute the instructions.
        function.instructions().iter().try_for_each(|instruction| instruction.evaluate(&mut stack))?;
        function.instructions().iter().try_for_each(|instruction| instruction.execute(&mut stack))?;

        // Load the outputs.
        let outputs = function.outputs().iter().map(|output| {
            // Retrieve the circuit output from the register.
            let circuit_output = stack.load_circuit(&Operand::Register(output.register().clone()))?;
            // Construct the circuit output value.
            let output = match (circuit_output, output.value_type()) {
                (CircuitValue::Plaintext(plaintext), ValueType::Constant(..)) => circuit::Value::Constant(plaintext),
                (CircuitValue::Plaintext(plaintext), ValueType::Public(..)) => circuit::Value::Public(plaintext),
                (CircuitValue::Plaintext(plaintext), ValueType::Private(..)) => circuit::Value::Private(plaintext),
                (CircuitValue::Record(record), ValueType::Record(..)) => circuit::Value::Record(record),
                _ => bail!("Circuit value does not match the expected output type"),
            };
            // Return the output.
            Ok(output)
        });

        outputs.collect()
    }
}
