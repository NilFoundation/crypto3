//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_MARSHALLING_FAST_KNOWLEDGE_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FAST_KNOWLEDGE_COMMITMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/container/sparse_vector.hpp>

#include <nil/crypto3/marshalling/algebra/types/fast_curve_element.hpp>

#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<
                    typename TTypeBase,
                    typename KnowledgeCommitment,
                    typename = typename std::enable_if<
                        std::is_same<KnowledgeCommitment,
                                     zk::commitments::knowledge_commitment<typename KnowledgeCommitment::type1,
                                                                           typename KnowledgeCommitment::type2>>::value,
                        bool>::type,
                    typename... TOptions>
                using fast_knowledge_commitment =
                    nil::marshalling::types::bundle<TTypeBase,
                                                    std::tuple<
                                                        // g
                                                        fast_curve_element<TTypeBase, typename KnowledgeCommitment::type1>,
                                                        // h
                                                        fast_curve_element<TTypeBase, typename KnowledgeCommitment::type2>>>;

                template<typename KnowledgeCommitment, typename Endianness>
                fast_knowledge_commitment<nil::marshalling::field_type<Endianness>, KnowledgeCommitment>
                    fill_fast_knowledge_commitment(const typename KnowledgeCommitment::value_type &kc) {

                    auto filled_g = fill_fast_curve_element<typename KnowledgeCommitment::type1, Endianness>(kc.g);
                    auto filled_h = fill_fast_curve_element<typename KnowledgeCommitment::type2, Endianness>(kc.h);

                    return fast_knowledge_commitment<nil::marshalling::field_type<Endianness>, KnowledgeCommitment>(
                        std::make_tuple(filled_g, filled_h));
                }

                template<typename KnowledgeCommitment, typename Endianness>
                typename KnowledgeCommitment::value_type
                    make_fast_knowledge_commitment(const fast_knowledge_commitment<nil::marshalling::field_type<Endianness>,
                                                                         KnowledgeCommitment> &filled_kc) {

                    return typename KnowledgeCommitment::value_type(std::move(make_fast_curve_element<typename KnowledgeCommitment::type1, Endianness>(std::get<0>(filled_kc.value()))),
                                                                    std::move(make_fast_curve_element<typename KnowledgeCommitment::type2, Endianness>(std::get<1>(filled_kc.value()))));
                }

                template<typename KnowledgeCommitment, typename Endianness>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    fast_knowledge_commitment<nil::marshalling::field_type<Endianness>, KnowledgeCommitment>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    fill_fast_knowledge_commitment_vector(
                        const std::vector<typename KnowledgeCommitment::value_type> &kc_vector) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using kc_element_type = fast_knowledge_commitment<TTypeBase, KnowledgeCommitment>;

                    using kc_element_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        kc_element_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>;

                    kc_element_vector_type result;

                    std::vector<kc_element_type> &val = result.value();
                    for (std::size_t i = 0; i < kc_vector.size(); i++) {
                        val.push_back(fill_fast_knowledge_commitment<KnowledgeCommitment, Endianness>(kc_vector[i]));
                    }
                    return result;
                }

                template<typename KnowledgeCommitment, typename Endianness>
                std::vector<typename KnowledgeCommitment::value_type> make_fast_knowledge_commitment_vector(
                    const nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        fast_knowledge_commitment<nil::marshalling::field_type<Endianness>, KnowledgeCommitment>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                        &filled_kc_vector) {

                    std::vector<typename KnowledgeCommitment::value_type> result;
                    const std::vector<
                        fast_knowledge_commitment<nil::marshalling::field_type<Endianness>, KnowledgeCommitment>> &values =
                        filled_kc_vector.value();
                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result.push_back(make_fast_knowledge_commitment<KnowledgeCommitment, Endianness>(values[i]));
                    }
                    return result;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FAST_KNOWLEDGE_COMMITMENT_HPP
