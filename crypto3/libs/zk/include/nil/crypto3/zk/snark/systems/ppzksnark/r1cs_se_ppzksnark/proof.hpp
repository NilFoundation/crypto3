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

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_PROOF_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_PROOF_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proof for the R1CS SEppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_proof {

                    typedef CurveType curve_type;

                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;

                public:
                    typename g1_type::value_type A;
                    typename g2_type::value_type B;
                    typename g1_type::value_type C;

                    r1cs_se_ppzksnark_proof() {
                    }
                    r1cs_se_ppzksnark_proof(typename g1_type::value_type &&A,
                                            typename g2_type::value_type &&B,
                                            typename g1_type::value_type &&C) :
                        A(std::move(A)),
                        B(std::move(B)), C(std::move(C)) {};

                    std::size_t G1_size() const {
                        return 2;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * g1_type::value_bits + G2_size() * g2_type::value_bits;
                    }

                    bool is_well_formed() const {
                        return (A.is_well_formed() && B.is_well_formed() && C.is_well_formed());
                    }

                    bool operator==(const r1cs_se_ppzksnark_proof &other) const {
                        return (this->A == other.A && this->B == other.B && this->C == other.C);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP
