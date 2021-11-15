//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP
#define CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename RedshiftProof,
                         typename = typename std::enable_if<
                             std::is_same<RedshiftProof, 
                                nil::crypto3::zk::snark::redshift_proof<
                                    typename RedshiftProof::hash_type,
                                    RedshiftProof::arity
                                >
                             >::value,
                             bool>::type,
                         typename... TOptions>
                using redshift_proof = 
                    nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::vector<typename CommitmentSchemeType::commitment_type> f_commitments
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                merkle_proof<
                                    TTypeBase,
                                    typename RedshiftProof::lpc::openning_type
                                >,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<
                                        TTypeBase,
                                        std::size_t
                                    >
                                >
                            >,
                            // typename CommitmentSchemeType::commitment_type P_commitment
                            merkle_proof<
                                TTypeBase,
                                typename RedshiftProof::lpc::openning_type
                            >,
                            // typename CommitmentSchemeType::commitment_type Q_commitment
                            merkle_proof<
                                TTypeBase,
                                typename RedshiftProof::lpc::openning_type
                            >,
                            // std::vector<typename CommitmentSchemeType::commitment_type> T_commitments
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                merkle_proof<
                                    TTypeBase,
                                    typename RedshiftProof::lpc::openning_type
                                >,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<
                                        TTypeBase,
                                        std::size_t
                                    >
                                >
                            >,
                            // std::vector<typename CommitmentSchemeType::proof_type> f_lpc_proofs
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                lpc_proof<
                                    TTypeBase,
                                    typename RedshiftProof::lpc
                                >,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<
                                        TTypeBase,
                                        std::size_t
                                    >
                                >
                            >,
                            // typename CommitmentSchemeType::proof_type P_lpc_proof
                            lpc_proof<
                                TTypeBase,
                                typename RedshiftProof::lpc
                            >,
                            // typename CommitmentSchemeType::proof_type Q_lpc_proof
                            lpc_proof<
                                TTypeBase,
                                typename RedshiftProof::lpc
                            >,
                            // std::vector<typename CommitmentSchemeType::proof_type> T_lpc_proofs
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                lpc_proof<
                                    TTypeBase,
                                    typename RedshiftProof::lpc
                                >,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<
                                        TTypeBase,
                                        std::size_t
                                    >
                                >
                            >
                        >
                    >;
            }    // namespace types
        }        // namespace marshalling
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_REDSHIFT_PROOF_HPP
