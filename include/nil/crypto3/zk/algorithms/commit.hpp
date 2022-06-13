//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_COMMIT_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_COMMIT_HPP

#include <nil/crypto3/zk/algorithms/precommit.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            // basic_fri
            template<typename FRI,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                        typename FRI::merkle_tree_hash_type,
                                                                        typename FRI::transcript_hash_type, FRI::m>,
                                         FRI>::value ||
                             std::is_base_of<commitments::detail::basic_batched_fri<
                                                 typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                 typename FRI::transcript_hash_type, FRI::m>,
                                             FRI>::value,
                         bool>::type = true>
            static typename FRI::commitment_type commit(typename FRI::precommitment_type P) {
                return P.root();
            }

            template<typename FRI, std::size_t list_size,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                        typename FRI::merkle_tree_hash_type,
                                                                        typename FRI::transcript_hash_type, FRI::m>,
                                         FRI>::value,
                         bool>::type = true>
            static std::array<typename FRI::commitment_type, list_size>
                commit(std::array<typename FRI::precommitment_type, list_size> P) {

                std::array<typename FRI::commitment_type, list_size> commits;
                for (std::size_t i = 0; i < list_size; i++) {
                    commits[i] = commit(P);
                }
                return commits;
            }

            template<typename FRI, typename PolynomialType,
                     typename std::enable_if<
                         std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                        typename FRI::merkle_tree_hash_type,
                                                                        typename FRI::transcript_hash_type, FRI::m>,
                                         FRI>::value ||
                             std::is_base_of<commitments::detail::basic_batched_fri<
                                                 typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                 typename FRI::transcript_hash_type, FRI::m>,
                                             FRI>::value,
                         bool>::type = true>
            static typename FRI::commitment_type
                commit(PolynomialType &f, const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {
                return commit<FRI>(precommit<FRI>(f, D));
            }

            // fri

            // basic_batched_fri

        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_COMMIT_HPP
