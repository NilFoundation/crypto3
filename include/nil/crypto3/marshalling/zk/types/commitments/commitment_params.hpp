//---------------------------------------------------------------------------//
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // Suddenly, we must distinguish between fri and kzg, and we will do it by checking for
                // existance of the field "precommitment_type", which exists only in fri.
                // Both singlethreaded and actor versions of fri must match this type-trait.
                template <typename CommitmentType>
                struct is_fri_commitment {
                    template <typename U>
                    static std::true_type test(decltype(U::precommitment_type)*);
                
                    template <typename>
                    static std::false_type test(...);
                
                    // A constexpr boolean indicating if the field exists in T
                    static constexpr bool value = decltype(test<T>(nullptr))::value;
                };

                template <typename TTypeBase, typename FieldElementType>
                using field_element_vector_type = nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, FieldElementType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                // TODO(martun): Move this somewhere shared, this code is duplicated a lot.
                template<typename integral_type>
                using marshalling_integral_type = nil::marshalling::types::integral<TTypeBase, integral_type>;

                template<typename integral_type>
                using integral_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        marshalling_integral_type,
                        nil::marshalling::option::sequence_size_field_prefix<marshalling_integral_type>>;

                template<typename InputContainer>
                integral_vector_type<typename InputContainer::value_type> make_integral_vector(
                        const InputContainer& input_container) {
                    integral_vector_type<integral_type> filled_vector;

                    std::vector<integral_type> &filled_vector_val = filled_vector.value();
                    for (const auto& element: input_container) {
                        filled_vector_val.push_back(integral_type(element));
                    }
                    return filled_vector;
                }

                // ******************* Marshalling of commitment params for Basic Fri and KZG. ********************************* //

                // Define commitment_params marshalling type for FRI.
                template<typename TTypeBase, typename CommitmentParamsType,
                    typename std::enable_if<is_fri_commitment<CommitmentParamsType>::value, bool>::type = true>
                using commitment_params = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
//                      constexpr static std::size_t lambda;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static std::size_t m;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      constexpr static std::uint32_t grinding_type::mask; If use_grinding==false, this will be 0.
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      const std::size_t max_degree;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      const std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;
//                      For each evaluation_domain we will include the unity root only.
                        field_element_vector_type<TTypeBase, typename CommitmentParamsType::field_type::value_type>,
//                      const std::vector<std::size_t> step_list;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            integral_type,
                            nil::marshalling::option::sequence_size_field_prefix<integral_type>>>,
//                      const std::size_t expand_factor;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                    >
                >;

                // Marshalling function for FRI params.
                template<typename Endianness, typename CommitmentParamsType,
                    typename std::enable_if<is_fri_commitment<CommitmentParamsType>::value, bool>::type = true>
                commitment_params<nil::marshalling::field_type<Endianness>, CommitmentParamsType>
                fill_commitment_params(const CommitmentParamsType &fri_params) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using FieldType = typename CommitmentParamsType::field_type;
                    using result_type = commitment_params<TTypeBase, CommitmentParamsType>;

                    std::vector<typename FieldType::value_type> D_unity_roots;
                    for (const auto& domain : fri_params.D) {
                        D_unity_roots.push_back(domain.get_unity_root());
                    }

                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.lambda),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.m),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.use_grinding ? grinding_type::mask: 0),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.max_degree),
                        nil::crypto3::marshalling::types::make_field_element_vector<
                            typename FieldType::value_type, Endianness>(D_unity_roots),
                        make_integral_vector(fri_params.step_list),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.expand_factor),
                    ));
                }


                // Define commitment_params marshalling type for KZG.
                template<typename TTypeBase, typename CommitmentParamsType,
                    typename std::enable_if<!is_fri_commitment<CommitmentParamsType>::value, bool>::type = true>
                using commitment_params = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
//                      std::vector<typename curve_type::template g1_type<>::value_type> commitment_key;
                        field_element_vector_type<TTypeBase, typename CommitmentParamsType::field_type::value_type>,
//                      verification_key_type verification_key;                        
                        field_element<TTypeBase, typename CommitmentParamsType::field_type::value_type>
                    >
                >;

                // Marshalling function for KZG params.
                template<typename Endianness, typename CommitmentParamsType,
                    typename std::enable_if<!is_fri_commitment<CommitmentParamsType>::value, bool>::type = true>
                commitment_params<nil::marshalling::field_type<Endianness>, CommitmentParamsType>
                fill_commitment_params(const CommitmentParamsType &kzg_params) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using FieldType = typename CommitmentParamsType::field_type;
                    using result_type = commitment_params<TTypeBase, CommitmentParamsType>;

TODO: Here we have 2 different groups, take care of that.
                    return result_type(std::make_tuple(
                        nil::crypto3::marshalling::types::make_field_element_vector<
                            typename FieldType::value_type, Endianness>(kzg_params.commitment_key),
                        field_element<TTypeBase, typename FieldType::value_type>(verification_key)
                    ));
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
