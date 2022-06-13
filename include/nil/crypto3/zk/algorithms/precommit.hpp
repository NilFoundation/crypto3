//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_PRECOMMIT_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_PRECOMMIT_HPP

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            // basic_fri
            template<typename FRI,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                       typename FRI::merkle_tree_hash_type,
                                                                       typename FRI::transcript_hash_type,
                                                                       FRI::m>,
                                                             FRI>::value,
                                             bool>::type = true>
            static typename FRI::precommitment_type
                precommit(math::polynomial_dfs<typename FRI::field_type::value_type> f,
                          const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                if (f.size() != D->size()) {
                    f.resize(D->size());
                }
                std::vector<std::array<std::uint8_t, FRI::field_element_type::length()>> y_data;
                y_data.resize(D->size());

                for (std::size_t i = 0; i < D->size(); i++) {
                    typename FRI::field_element_type y_val(f[i]);
                    auto write_iter = y_data[i].begin();
                    y_val.write(write_iter, FRI::field_element_type::length());
                }

                return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, 2>(y_data.begin(),
                                                                                            y_data.end());
            }

            template<typename FRI,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                       typename FRI::merkle_tree_hash_type,
                                                                       typename FRI::transcript_hash_type,
                                                                       FRI::m>,
                                                             FRI>::value,
                                             bool>::type = true>
            static typename FRI::precommitment_type
                precommit(const math::polynomial<typename FRI::field_type::value_type> &f,
                          const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                math::polynomial_dfs<typename FRI::field_type::value_type> f_dfs;
                f_dfs.from_coefficients(f);

                return precommit<FRI>(f_dfs, D);
            }

            template<typename FRI,
                     std::size_t list_size,
                     typename PolynomialType,
                     typename std::enable_if<std::is_base_of<commitments::detail::basic_fri<typename FRI::field_type,
                                                                       typename FRI::merkle_tree_hash_type,
                                                                       typename FRI::transcript_hash_type,
                                                                       FRI::m>,
                                                             FRI>::value,
                                             bool>::type = true>
            static std::array<typename FRI::precommitment_type, list_size>
                precommit(const std::array<PolynomialType, list_size> &poly,
                          const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &domain) {
                std::array<typename FRI::precommitment_type, list_size> precommits;
                for (std::size_t i = 0; i < list_size; i++) {
                    precommits[i] = precommit(poly[i], domain);
                }
                return precommits;
            }

            // fri

            // basic_batched_fri
            template<typename FRI, typename ContainerType, typename std::enable_if<std::is_base_of<commitments::detail::basic_batched_fri<
                                                                                                       typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                                                                       typename FRI::transcript_hash_type, FRI::m>,
                                                                                                   FRI>::value,
                                                                                   bool>::type = true>
            static typename std::enable_if<
                (std::is_same<typename ContainerType::value_type,
                              math::polynomial_dfs<typename FRI::field_type::value_type>>::value),
                typename FRI::precommitment_type>::type
                precommit(ContainerType poly,
                          const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                auto begin = std::chrono::high_resolution_clock::now();
                auto last = begin;
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - last);
#endif
                for (int i = 0; i < poly.size(); ++i) {
                    // assert (poly[i].size() == D->size());
                    if (poly[i].size() != D->size()) {
                        poly[i].resize(D->size());
                    }
                }

                std::size_t list_size = poly.size();
                std::vector<std::vector<std::uint8_t>> y_data(D->size());

                for (std::size_t i = 0; i < D->size(); i++) {
                    y_data[i].resize(FRI::field_element_type::length() * list_size);
                    for (std::size_t j = 0; j < list_size; j++) {

                        typename FRI::field_element_type y_val(poly[j][i]);
                        auto write_iter = y_data[i].begin() + FRI::field_element_type::length() * j;
                        y_val.write(write_iter, FRI::field_element_type::length());
                    }
                }

                return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, 2>(y_data.begin(),
                                                                                                y_data.end());
            }

            template<typename FRI, typename ContainerType, typename std::enable_if<std::is_base_of<commitments::detail::basic_batched_fri<
                                                               typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                               typename FRI::transcript_hash_type, FRI::m>,
                                                           FRI>::value,
                                       bool>::type = true>
            static typename std::enable_if<
                (std::is_same<typename ContainerType::value_type,
                              math::polynomial<typename FRI::field_type::value_type>>::value),
                typename FRI::precommitment_type>::type
                precommit(const ContainerType &poly,
                          const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D) {

                std::size_t list_size = poly.size();
                std::vector<math::polynomial_dfs<typename FRI::field_type::value_type>> poly_dfs(list_size);
                for (std::size_t i = 0; i < list_size; i++) {
                    poly_dfs[i].from_coefficients(poly[i]);
                    poly_dfs[i].resize(D->size());
                }

                return precommit<FRI>(poly_dfs, D);
            }

        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_PRECOMMIT_HPP
