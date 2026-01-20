# So what IS poseidon, exactly?

Poseidon is a permutation used within a [Sponge function](https://en.wikipedia.org/wiki/Sponge_function). 
Here's a nice [semi-technical explanation](https://autoparallel.github.io/poseidon/sponge.html) of what a sponge function is.
Basically, a sponge is an operation that involves "absorbing" or taking an input and mixing it with an internal 
state, and then "squeezing" or taking a partial output from that state. This permutation is applied repeatedly.
Poseidon is used in order to make algebraic hash functions over finite fields, in this case the scalar field of
the bn254 curve.

What this means in essence is that we build a hash function based on these poseidon permutations that can take in 
a vector of field elements and return an output of a preset size, which is a hash of our input. This hash function
is used for every value that has to be used inside of a ZK circuit, because the usual hash functions like SHA-265 
have a very high constraint cost compared to poseidon.


# Why Poseidon and not SHA-256?

ZK proving systems are based on polynomial math. Any computer algorithm that needs to be computed within a ZK circuit
needs to be represented as a series of polynomial operations, also known as an arithmetic circuit. This conversion 
process is known as arithmetization. The problem with SHA-256 and other similar hash functions is that they're designed
to run well on a CPU, and thus use bit operations(xor, bit flips, bit shifts, etc.) as the source of non-linearity. 
These operations are obviously a lot harder to represent algebraically than operations like multiplication, exponentiation, etc.
This is the reason why we need hashing algorithms based on algebraic operations like poseidon or keccak.


# Poseidon function parameters.

"Poseidon function" doesn't refer to a single hash function (like SHA-256) but a family of hash functions, or more
accurately a family of sponge constructions that are based on the poseidon permutation. Each of these individual 
functions is constructed based on a set of parameters. If you change one of these parameters, you change the function 
itself. Another way to view it is that the set of parameters that defines your poseidon function IS the function and 
its definition. Additionally, these parameters can have a big impact on performance.

We use circom for our ZK circuits, and whatever parameters are used by circom for their poseidon hash are the same
ones that we should use in our source code. These must be defined explicitly and are part of the specification.

This is a simplified explanation of what's happening inside our poseidon function

### Summary

Each hash function consists of multiple rounds of permutations. During each of these permutations, there are three
operations that take place: Adding round constants, Applying a substitution box, and applying an MDS matrix.

### 1. Input and absorption

The poseidon function works on an internal state vector with **t** elements, where each value is an Fr type i.e a 
member of the scalar field of an elliptic curve (Here, BN254)

```
state = [x1, x2, ......x(t-1)]
```

The hash function takes in a vector containing **r** elements, where r is our number of inputs, and adds **c** unrelated 
elements to form a total of **t**. Here, r is our rate(number of inputs) and c is our capacity(state elements reserved
for security). Together, your rate and capacity decide the size of the state for each permutation. A larger state means
heavier ZK computiation and more constraints. The pre-existing poseidon variants are optimised to have good security with
the smallest necessary state and number of rounds. 

For a binary merkle tree like the one used in our attribute tree, where each node is the hash of its two children, we 
give two inputs: the left child and the right child.

### 2. Permutation: Adding round constants

Each round of permutation starts by adding a pre-defined constant to each element of the state vector.

```
state = [x1, x2, x3, x4]

for i in range(0, t-1):
    state[i] = state[i] + round_constants[round][i]
```

This breaks symmetry between rounds. The variable name for this set of constants is `ark`.

### 3. Permutation: Substitution box (S-box)

A substitution box is a way to apply a non linear transformation to your state. In poseidon, this is done through 
exponentiation by a factor of `alpha`. Alpha is an odd number, [usually 3 or 5](https://autoparallel.github.io/poseidon/s-boxes.html#why-choose-x3-and-x), mostly 5. The higher the alpha the better the security,but obviously this comes at a performance cost.

```
state = [x1, x2, x3, x4]

for i in range(0, t-1):
    state[i] = state[i] ^ alpha
```

The above Pseudocode describles a full round, where every state element is transformed. There are also a number of
partial rounds, where only one element in the state is transformed. This massively saves on performance, and is
allowable security wise because the next step propogates this transformation to the whole set.

The number of full rounds is `full_rounds`, and the number of partial rounds is `partial_rounds`

### 4. Permutation: MDS matrix multiplication

An MDS or a Maximum Distance Separable matrix is a square matrix where every subset of rows and columns is linearly 
independent. What this means in practice is that if you look at the vectors in this matrix, each vector adds a new 
dimension, and no two vectors lie on the same line (or three vectors on the same plane, so on and so forth).

These matrices are pre-defined t x t matrices composed of field elements. The variable name in the ark library
is `mds`.

```
state = [x1,x2,x3,x4]
new_state = [0,0,0,0]

for i in range(0,t-1):
    for j in range(0,t-1):
        new_state[i] += MDS[i][j] * state[j]

state = new_state
```

### 5. Output

The permutation rounds are redone as many times as defined by `full_rounds` and `partial_rounds`. Finally, you
get a field element of a fixed size that's a hash of your inputs.

# Practical considerations

the `ark-crypto-primitives` library exposes the following struct to us

```rust
pub struct PoseidonConfig<F: PrimeField> {
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Exponent used in S-boxes.
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: Vec<Vec<F>>,
    /// The rate (in terms of number of field elements).
    /// See [On the Indifferentiability of the Sponge Construction](https://iacr.org/archive/eurocrypt2008/49650180/49650180.pdf)
    /// for more details on the rate and capacity of a sponge.
    pub rate: usize,
    /// The capacity (in terms of number of field elements).
    pub capacity: usize,
}
```

We must find the circom constants used, and write our poseidon hash function using those constants, our 
parameters and the provided functions that take this struct as input.