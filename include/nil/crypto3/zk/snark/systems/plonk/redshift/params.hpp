//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PARAMS_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PARAMS_HPP

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType,
                         std::size_t WitnessColumns = 15,
                         std::size_t PublicInputColumns = 15,
                         std::size_t ConstantColumns = 15,
                         std::size_t SelectorColumns = 15,
                         typename MerkleTreeHashType = hashes::keccak_1600<512>,
                         typename TranscriptHashType = hashes::keccak_1600<512>, std::size_t Lambda = 40,
                         std::size_t R = 1, std::size_t M = 2>
                struct redshift_params {

                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t witness_columns = WitnessColumns;
                    constexpr static const std::size_t public_input_columns = PublicInputColumns;
                    constexpr static const std::size_t constant_columns = ConstantColumns;
                    constexpr static const std::size_t selector_columns = SelectorColumns;

                    constexpr static const typename FieldType::value_type delta = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

                    typedef commitments::list_polynomial_commitment_params<MerkleTreeHashType, TranscriptHashType, Lambda, R, M>
                            commitment_params_type;
                    
                    constexpr static const std::size_t opening_points_public = 1;
                    typedef commitments::list_polynomial_commitment<FieldType,
                                                              commitment_params_type,
                                                              opening_points_public>
                        commitment_scheme_public_type;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PARAMS_HPP
