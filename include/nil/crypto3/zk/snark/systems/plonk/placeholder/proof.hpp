//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                constexpr std::size_t FIXED_VALUES_BATCH = 0;
                constexpr std::size_t VARIABLE_VALUES_BATCH = 1;
                constexpr std::size_t PERMUTATION_BATCH =2;
                constexpr std::size_t QUOTIENT_BATCH = 3;
                constexpr std::size_t LOOKUP_BATCH = 4;

                /**
                 * A proof for the Placeholder scheme.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for marshalling purposes.
                 */
                template<typename FieldType, typename ParamsType>
                struct placeholder_proof {
                    static constexpr std::size_t FIXED_VALUES_BATCH = 0;
                    static constexpr std::size_t VARIABLE_VALUES_BATCH = 1;
                    static constexpr std::size_t PERMUTATION_BATCH =2;
                    static constexpr std::size_t QUOTIENT_BATCH = 3;
                    static constexpr std::size_t LOOKUP_BATCH = 4;

                    typedef FieldType field_type;
                    typedef ParamsType params_type;

                    using circuit_params_type = typename ParamsType::circuit_params_type;
                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;

                    struct evaluation_proof {
                        // TODO: remove it!
                        typename FieldType::value_type challenge;

                        typename commitment_scheme_type::proof_type eval_proof;

                        bool operator==(const evaluation_proof &rhs) const {
                            return challenge == rhs.challenge && eval_proof == rhs.eval_proof;
                        }
                        bool operator!=(const evaluation_proof &rhs) const {
                            return !(rhs == *this);
                        }
                    };

                    placeholder_proof() {
                    }

                    std::map<std::size_t, commitment_type> commitments;
                    evaluation_proof eval_proof;

                    bool operator==(const placeholder_proof &rhs) const {
                        return
                            commitments == rhs.commitments &&
                            eval_proof == rhs.eval_proof;
                    }
                    bool operator!=(const placeholder_proof &rhs) const {
                        return !(rhs == *this);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP
