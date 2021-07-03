//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_PPZKSNARK_PROOF_HPP
#define CRYPTO3_R1CS_PPZKSNARK_PROOF_HPP

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proof for the R1CS ppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_proof {
                    typedef CurveType curve_type;
                    using g1_type = typename CurveType::g1_type;
                    using g2_type = typename CurveType::g2_type;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;

                public:
                    typename knowledge_commitment<g1_type, g1_type>::value_type g_A;
                    typename knowledge_commitment<g2_type, g1_type>::value_type g_B;
                    typename knowledge_commitment<g1_type, g1_type>::value_type g_C;
                    g1_value_type g_H;
                    g1_value_type g_K;

                    r1cs_ppzksnark_proof() {
                        // invalid proof with valid curve points
                        this->g_A.g = g1_value_type::one();
                        this->g_A.h = g1_value_type::one();
                        this->g_B.g = g2_value_type::one();
                        this->g_B.h = g1_value_type::one();
                        this->g_C.g = g1_value_type::one();
                        this->g_C.h = g1_value_type::one();
                        this->g_H = g1_value_type::one();
                        this->g_K = g1_value_type::one();
                    }
                    r1cs_ppzksnark_proof(typename knowledge_commitment<g1_type, g1_type>::value_type &&g_A,
                                         typename knowledge_commitment<g2_type, g1_type>::value_type &&g_B,
                                         typename knowledge_commitment<g1_type, g1_type>::value_type &&g_C,
                                         g1_value_type &&g_H,
                                         g1_value_type &&g_K) :
                        g_A(std::move(g_A)),
                        g_B(std::move(g_B)), g_C(std::move(g_C)), g_H(std::move(g_H)), g_K(std::move(g_K)) {};

                    std::size_t G1_size() const {
                        return 7;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::value_bits + G2_size() * CurveType::g2_type::value_bits;
                    }

                    bool is_well_formed() const {
                        return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                g_H.is_well_formed() && g_K.is_well_formed());
                    }

                    bool operator==(const r1cs_ppzksnark_proof &other) const {
                        return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                                this->g_H == other.g_H && this->g_K == other.g_K);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
