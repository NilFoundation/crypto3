//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP

#include <nil/crypto3/zk/snark/commitments/polynmomial/pedersen.hpp>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <map>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                size_t const CHALLENGE_LENGTH_IN_LIMBS = 2;

                template<typename FieldType>
                struct ScalarChallenge {
                    FieldType to_field(FieldType endo_coeff) {
                        uint64_t length_in_bits = (64 * CHALLENGE_LENGTH_IN_LIMBS);
                        FieldType rep = _val;

                        FieldType a = 2;
                        FieldType b = 2;

                        FieldType one = FieldType::one();
                        FieldType neg_one = -one;

                        for (int32_t i = length_in_bits / 2 - 1; i >= 0; --i) {
                            a.double_in_place();
                            b.double_in_place();

                            bool r_2i = get_bit(rep, 2 * i);
                            FieldType s;
                            if (r_2i) {
                                s = one;
                            } else {
                                s = neg_one;
                            }
                            if get_bit(rep, 2 * i + 1) == 0 {
                                b += s;
                            } else {
                                a += s;
                            }
                        }

                        return a * endo_coeff + b;
                    };

                    FieldType _val;
                };

                enum GateType {
                    /// Zero gate
                    Zero = 0,
                    /// Generic arithmetic gate
                    Generic = 1,
                    /// Poseidon permutation gate
                    Poseidon = 2,
                    /// Complete EC addition in Affine form
                    CompleteAdd = 3,
                    /// EC variable base scalar multiplication
                    VarBaseMul = 4,
                    /// EC variable base scalar multiplication with group endomorphim optimization
                    EndoMul = 5,
                    /// Gate for computing the scalar corresponding to an endoscaling
                    EndoMulScalar = 6,
                    /// ChaCha
                    ChaCha0 = 7,
                    ChaCha1 = 8,
                    ChaCha2 = 9,
                    ChaChaFinal = 10,
                };

                enum ArgumentType {
                    /// Gates in the PLONK constraint system.
                    /// As gates are mutually exclusive (a single gate is set per row),
                    /// we can reuse the same powers of alpha across gates.
                    GateType,
                    /// The permutation argument
                    Permutation,
                    /// The lookup argument
                    Lookup
                };

                template<typename FieldType>
                struct Alphas {
                    /// The next power of alpha to use
                    /// the end result will be [1, alpha^{next_power - 1}]
                    uint32_t next_power;
                    /// The mapping between constraint types and powers of alpha
                    std::map<ArgumentType, std::pair<uint32_t, uint32_t>> mapping;
                    /// The powers of alpha: 1, alpha, alpha^2, etc.
                    /// If set to [Some], you can't register new constraints.
                    std::vector<FieldType> alphas;
                };

                template<typename CurveType>
                struct srs_t {
                    /// The vector of group elements for committing to polynomials in coefficient form
                    std::vector<CurveType> g;
                    /// A group element used for blinding commitments
                    CurveType h;
                    // TODO: the following field should be separated, as they are optimization values
                    /// Commitments to Lagrange bases, per domain size
                    std::map<size_t, std::vector<CurveType>> lagrange_bases;
                    /// Coefficient for the curve endomorphism
                    typename CurveType::scalar_field_type endo_r;
                    /// Coefficient for the curve endomorphism
                    typename CurveType::base_field_type endo_q;
                };

                template<typename FieldType>
                struct ArithmeticSpongeParams {
                    std::vector<std::vector<FieldType>> round_constants;
                    std::vector<std::vector<FieldType>> mds;
                };

                enum PolishToken {
                    Alpha,
                    Beta,
                    Gamma,
                    JointCombiner,
                    EndoCoefficient,
                    Mds,
                    Literal,
                    Cell,
                    Dup,
                    Pow,
                    Add,
                    Mul,
                    Sub,
                    VanishesOnLast4Rows,
                    UnnormalizedLagrangeBasis,
                    Store,
                    Load
                };

                struct linearization_t {
                    std::vector<PolishToken> constant_term;
                    std::vector<PolishToken> index_term;
                };

                template<typename CurveType, std::size_t WiresAmount>
                typedef pedersen_commitment_scheme<CurveType> commitment_scheme;
                struct lookup_verifier_index {
                    enum lookups_used {
                        Single,
                        Joint,
                    } lookup_used;
                    std::vector<commitment_scheme> lookup_table;
                    std::vector<commitment_scheme> lookup_selectors;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
};               // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_PICKLES_DETAIL_HPP
