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

#ifndef CRYPTO3_USCS_PPZKSNARK_PROOF_HPP
#define CRYPTO3_USCS_PPZKSNARK_PROOF_HPP

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proof for the USCS ppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                struct uscs_ppzksnark_proof {
                    typedef CurveType curve_type;

                    typename CurveType::g1_type::value_type V_g1;
                    typename CurveType::g1_type::value_type alpha_V_g1;
                    typename CurveType::g1_type::value_type H_g1;
                    typename CurveType::g2_type::value_type V_g2;

                    uscs_ppzksnark_proof() :
                        V_g1(CurveType::g1_type::value_type::one()), alpha_V_g1(CurveType::g1_type::value_type::one()),
                        H_g1(CurveType::g1_type::value_type::one()), V_g2(CurveType::g2_type::value_type::one()) {
                        // invalid proof with valid curve points
                    }
                    uscs_ppzksnark_proof(typename CurveType::g1_type::value_type &&V_g1,
                                         typename CurveType::g1_type::value_type &&alpha_V_g1,
                                         typename CurveType::g1_type::value_type &&H_g1,
                                         typename CurveType::g2_type::value_type &&V_g2) :
                        V_g1(std::move(V_g1)),
                        alpha_V_g1(std::move(alpha_V_g1)), H_g1(std::move(H_g1)), V_g2(std::move(V_g2)) {};

                    std::size_t G1_size() const {
                        return 3;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::value_bits + G2_size() * CurveType::g2_type::value_bits;
                    }

                    bool is_well_formed() const {
                        return (V_g1.is_well_formed() && alpha_V_g1.is_well_formed() && H_g1.is_well_formed() &&
                                V_g2.is_well_formed());
                    }

                    bool operator==(const uscs_ppzksnark_proof &other) const {
                        return (this->V_g1 == other.V_g1 && this->alpha_V_g1 == other.alpha_V_g1 &&
                                this->H_g1 == other.H_g1 && this->V_g2 == other.V_g2);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
