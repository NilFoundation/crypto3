# =nil;Crypro3 Blueprint usage tutorial

This module is supposed to be used together with =nil;Crypto3 
[zk](https://github.com/NilFoundation/crypto3-zk). The blueprint module is used to generate the input data in form of a constraint system, while [crypto3-zk](https://github.com/NilFoundation/crypto3-zk) is used to process them as input for what to prove.

In this document, we introduce the very basic concepts of blueprint. For the example of usage please follow the [usage markdown](https://github.com/NilFoundation/crypto3-blueprint/blob/master/docs/usage.md) or look through the [simple example](https://github.com/NilFoundation/crypto3-blueprint/blob/master/example/simple_example.hpp).

## Preliminaries

If you are a developer who is completely new to zk-SNARKS we would recommend you to look through this [great resource](https://zkp.science) with the list of the most meaningfull zk-related papers and posts. You can find there both thorough pure-technical papers and high-level overview of zk technologies.

## Quick intro to R1CS

A *Rank One Constraint System* (R1CS) is a way to express a computation that makes it amenable to zero knowledge proofs. Basically any computation can be reduced (or flattened) to an R1CS. A single rank one constraint on a vector w is defined as

```
<A, w> * <B,w> = <C, w>
```

Where `A`, `B`, `C` are vectors of the same length as `w`, and `<>` denotes inner product of vectors. A R1CS is then a system of these kinds of equations:

```
<A_1, w> * <B_1,w> = <C_1, w>
<A_2, w> * <B_2,w> = <C_2, w>
...
<A_n, w> * <B_n,w> = <C_n, w>
```

The vector `w` is called a *witness* and zk-SNARK proofs can always be reduced to proving that *the prover knows a witness w such that the R1CS is satisfied*. 

## =nil;Crypto3 Blueprint basics: 

### 1. The Blueprint

In the =nil;Crypto3 Blueprint tool, the blueprint is where our "circuits" (i.e. R1CS and components) will be collected.

The C++ file defining the blueprint is [here](https://github.com/NilFoundation/crypto3-blueprint/blob/master/include/nil/crypto3/zk/snark/blueprint.hpp). We will first show how to add R1CS to the blueprint.

Let's assume, that we want to prove knowing of a value x that satisfies the equation

```
x^3 + x + 5 == 35.
```

We can make this a little more general, and say that given a publicly known output value `out`, we want to prove that we know `x` such that

```
x^3 + x + 5 == out.
```

Recall that we can introduce some new variables `sym_1, y, sym_2` and flatten the above equation into the following quadratic equations:

```
x * x = sym_1
sym_1 * x = y
y + x = sym_2
sym_2 + 5 = out
```

We can verify that the above system can be written as an R1CS with 

```
w = [one, x, out, sym_1, y, sym_2]
```

and the vectors `A_1, ..., A_4, B_1, ..., B4, C_1, ..., C_4` are given by

```
A_1 = [0, 1, 0, 0, 0, 0]
A_2 = [0, 0, 0, 1, 0, 0]
A_3 = [0, 1, 0, 0, 1, 0]
A_4 = [5, 0, 0, 0, 0, 1]
B_1 = [0, 1, 0, 0, 0, 0]
B_2 = [0, 1, 0, 0, 0, 0]
B_3 = [1, 0, 0, 0, 0, 0]
B_4 = [1, 0, 0, 0, 0, 0]
C_1 = [0, 0, 0, 1, 0, 0]
C_2 = [0, 0, 0, 0, 1, 0]
C_3 = [0, 0, 0, 0, 0, 1]
C_4 = [0, 0, 1, 0, 0, 0]
```

The original degree 3 polynomial equation has a solution `x=3` and we can verify that the R1CS has a corresponding solution

```
w = [1, 3, 35, 9, 27, 30].
```

Now let’s see how we can enter this R1CS into =nil;Crypto3 Blueprint, produce proofs and verify them. We will use the `blueprint_variable` type to declare our variables. See the file `test.cpp` for the full code. 

First lets define the finite field where all our values live, and initialize the curve parameters:

```
typedef libff::Fr<default_r1cs_ppzksnark_pp> field_type;
default_r1cs_ppzksnark_pp::init_public_params();
```

Next we define the blueprint and the variables we need. Note that the variable `one` is automatically defined in the blueprint.

```
blueprint<field_type> bp;

blueprint_variable<field_type> out;
blueprint_variable<field_type> x;
blueprint_variable<field_type> sym_1;
blueprint_variable<field_type> y;
blueprint_variable<field_type> sym_2;
```

Next we need to "allocate" the variables on the blueprint. This will associate the variables to a blueprint and will allow us to use the variables to define R1CS constraints.

```
out.allocate(bp);
x.allocate(bp);
sym_1.allocate(bp);
y.allocate(bp);
sym_2.allocate(bp);
```

Note that we are allocating the `out` variable first. This is because =nil;Crypto3 Blueprint divides the allocated variables in a blueprint into "primary" (i.e. public) and "auxiliary" (i.e. private) variables. To specify which variables are public and which ones are private we use the blueprint function `set_input_sizes(n)` to specify that the first `n` variables are public, and the rest are private. In our case we have one public variable `out`, so we use

```
bp.set_input_sizes(1);
```

to specify that the variable `out` should be public, and the rest private.

Next let's add the above R1CS constraints to the blueprint. This is straightforward once we have the variables allocated:

```
// x*x = sym_1
bp.add_r1cs_constraint(r1cs_constraint<field_type>(x, x, sym_1));

// sym_1 * x = y
bp.add_r1cs_constraint(r1cs_constraint<field_type>(sym_1, x, y));

// y + x = sym_2
bp.add_r1cs_constraint(r1cs_constraint<field_type>(y + x, 1, sym_2));

// sym_2 + 5 = out
bp.add_r1cs_constraint(r1cs_constraint<field_type>(sym_2 + 5, 1, out));
```

Now that we have our circuit in the form of R1CS constraints on the blueprint we can run the Generator and generate proving keys and verification keys for our circuit:

```
const r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

typename snark::r1cs_gg_ppzksnark<bls12<381>>::keypair_type keypair = generate<snark::r1cs_gg_ppzksnark<bls12<381>>>(constraint_system);
```

Note that the above is the so-called "trusted setup". We can access the proving key through `keypair.pk` and the verification key through `keypair.vk`.

Next we want to generate a proof. For this we need to set the values of the public variables in the blueprint, and also set witness values for the private variables:

```
bp.val(out) = 35;

bp.val(x) = 3;
bp.val(sym_1) = 9;
bp.val(y) = 27;
bp.val(sym_2) = 30;
```

Now that the values are set in the blueprint we can access the public values through `bp.primary_input()` and the private values through `bp.auxiliary_input()`. Let's use the proving key, the public inputs and the private inputs to create a proof that we know the witness values:

```
typename snark::r1cs_gg_ppzksnark<bls12<381>>::proof_type proof = prove<snark::r1cs_gg_ppzksnark<bls12<381>>>(keypair.pk, bp.primary_input(), bp.auxiliary_input());
```

Now that we have a proof we can also verify it, using the previously created `proof`, the verifying key `keypair.vk` and the public input `bp.primary_input()`:

```
bool verified = verify<snark::r1cs_gg_ppzksnark<bls12<381>>>(keypair.vk, bp.primary_input(), proof);
```

At this stage the boolean `verified` should have the value `true`, given that we put in the correct values for the witness variables.

### 2. Components

The =nil;Crypto3 Blueprint library uses *components* to package up R1CS into more manageable pieces and to create cleaner interfaces for developers. They do this by being a wrapper around a blueprint and handling generating R1CS constraints and also generating witness values.

We're going to show how to create a component for the example R1CS above in order to make it a bit more manageable.

First we create a new file `src/component.hpp` which contains the component file. In our case we want the developer using the component to be able to set the public variable `out`, as well as the private witness variable `x`, but the component itself would take care of the intermediate variables `y`, `sym_1` and `sym_2`.

Thus we create a class `test_component`, derived from the base `component` class which has the variables `y`, `sym_1` and `sym_2` as private members (in the C++ sense). The variables `x` and `out` will be public class member variables.

In the following sections we go over the functions of this component and how to use it.

## Constructor

As any component, the constructor takes as input a blueprint `bp`. We also have `blueprint_variable` inputs `x` and `out`. We assume that the user of the component has already allocated `x` and `out` to the blueprint.

The constructor then allocates the intermediate variables to the blueprint:

```
sym_1.allocate(this->bp);
y.allocate(this->bp);
sym_2.allocate(this->bp);
```

### Function `generate_r1cs_constraints()`

This function adds the R1CS constraints corresponding to the circuits. These are the same constraints as we added manually earlier, just bundled up inside this function.

### Function `generate_r1cs_witness()`

This function assumes that we've already set the public value `out`, and the witness value `x`. It then computes the inferred witness values for the intermediate variables `sym_1`, `y`, `sym_2`. Thus the user of the component never needs to worry about the intermediate variables.

## Using the component

In the file `src/test-component.cpp` we can see how the component it used. This file is very similar to the file in the previous section. We start as before by generating curve parameters. After this we initialize the blueprint, and allocate the variables `out`, `x` to the blueprint:

```
blueprint<field_type> bp;
blueprint_variable<field_type> out;
blueprint_variable<field_type> x;

out.allocate(bp);
x.allocate(bp);
```

After this we specify which variables are public and which are private (in the zk-SNARK sense). This would be `out` as the only public variable and the rest as private variables. We also create a new `test_component`:

```
bp.set_input_sizes(1);
test_component<field_type> g(bp, out, x);
```

Next generate the R1CS constraints by simply calling the corresponding function:

```
g.generate_r1cs_constraints();
```

Now we add the witness values. We add the value 35 for the public variable `out` and the value 3 for the witness variable `x`. The rest of the values will be computed inside the component:

```
bp.val(out) = 35;
bp.val(x) = 3;
g.generate_r1cs_witness();
```

That's it! Now we can run the Generator to generate proving and verification keys, create the proof and verify it as we did before.