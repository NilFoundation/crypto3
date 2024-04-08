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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template <typename TTypeBase, typename FieldElementType>
                using field_element_vector_type = nil::marshalling::types::array_list<
                    TTypeBase,
                    field_element<TTypeBase, FieldElementType>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                // ******************* Marshalling of commitment params for Basic Fri and KZG. ********************************* //

                template<typename Endianness, typename IntegerType>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, IntegerType>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>
                >
                    fill_integer_vector(const std::vector<IntegerType>& integral_vector) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using integral_type = nil::marshalling::types::integral<TTypeBase, IntegerType>;
                    using integral_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        integral_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >;

                    integral_vector_type result;

                    std::vector<integral_type> &val = result.value();
                    for (std::size_t i = 0; i < integral_vector.size(); i++) {
                        val.push_back(integral_type(integral_vector[i]));
                    }
                    return result;
                }

                template<typename Endianness, typename IntegerType>
                std::vector<IntegerType>
                 make_integer_vector(const nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, IntegerType>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>
                >& filled_vector) {
                    std::vector<IntegerType> result;
                    for( std::size_t i = 0; i < filled_vector.value().size(); i++){
                        result.push_back(filled_vector.value()[i].value());
                    }
                    return result;
                }

                // C++ does not allow partial specialization of alias templates, so we need to use a helper struct.
                // This struct will also be used for the dummy commitment params used in testing.
                template<typename TTypeBase, typename CommitmentParamsType, typename Enable = void>
                struct commitment_params{
                    using type = nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>,
                                nil::marshalling::types::integral<TTypeBase, std::size_t>
                            >
                        >;
                };

                // Marshalling function for dummy params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<
                    nil::marshalling::field_type<Endianness>, CommitmentSchemeType,
                    std::enable_if_t<!nil::crypto3::zk::is_lpc<CommitmentSchemeType> && !nil::crypto3::zk::is_kzg<CommitmentSchemeType>>
                >::type
                fill_commitment_params(const typename CommitmentSchemeType::params_type &dummy_params) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using result_type = typename commitment_params<TTypeBase, CommitmentSchemeType>::type;

                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(0),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(0)
                    ));
                }

                // Define commitment_params marshalling type for LPC.
                template<typename TTypeBase, typename CommitmentSchemeType>
                struct commitment_params<TTypeBase, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>> {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using integral_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using type =
                        nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
//                              constexpr static std::size_t lambda;
                                integral_type,
//                              constexpr static std::size_t m;
                                integral_type,
//                              constexpr static std::uint32_t grinding_type::mask; If use_grinding==false, this will be 0.
                                integral_type,
//                              const std::size_t max_degree;
                                integral_type,
//                              const std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;
//                              For each evaluation_domain we will include the unity root only.
                                field_element_vector_type<TTypeBase, typename CommitmentParamsType::field_type::value_type>,
//                              const std::vector<std::size_t> step_list;
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    integral_type,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        integral_type>
                                >,
//                              const std::size_t expand_factor;
                                integral_type
                            >
                        >;
                };

                // Marshalling function for FRI params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>>::type
                fill_commitment_params(const typename CommitmentSchemeType::params_type &fri_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using FieldType = typename CommitmentParamsType::field_type;
                    using result_type = typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType>::type;

                    std::vector<typename FieldType::value_type> D_unity_roots;
                    for (const auto& domain : fri_params.D) {
                        D_unity_roots.push_back(domain->get_unity_root());
                    }

                    return result_type(std::make_tuple(
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.lambda),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.m),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.use_grinding?fri_params.grinding_parameter:0),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.max_degree),
                        nil::crypto3::marshalling::types::fill_field_element_vector<
                            typename FieldType::value_type, Endianness>(D_unity_roots),
                        fill_integer_vector<Endianness>(fri_params.step_list),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.expand_factor)
                    ));
                }

                template<typename Endianness, typename CommitmentSchemeType>
                typename CommitmentSchemeType::params_type
                make_commitment_params(const typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>>::type &filled_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;

                    auto step_list = make_integer_vector<Endianness, std::size_t>(std::get<5>(filled_params.value()));
                    std::size_t lambda = std::get<0>(filled_params.value()).value();
                    std::size_t r = std::accumulate(step_list.begin(), step_list.end(), 0);
                    std::size_t max_degree = std::get<3>(filled_params.value()).value();
                    std::size_t expand_factor = std::get<6>(filled_params.value()).value();
                    std::size_t grinding_parameter = std::get<2>(filled_params.value()).value();
                    auto D =  math::calculate_domain_set<typename CommitmentParamsType::field_type>(r + expand_factor + 1, r);
                    // TODO: check generators correctness

                    return CommitmentParamsType(
                        max_degree,
                        D,
                        step_list,
                        expand_factor,
                        lambda,
                        (grinding_parameter != 0),
                        grinding_parameter
                    );
                }

                // Define commitment_params marshalling type for KZG.
                template<typename Endianness, typename CommitmentSchemeType>
                struct commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>> {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;

                    using type =
                        nil::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
//                              std::vector<typename curve_type::template g1_type<>::value_type> commitment_key;
                                nil::marshalling::types::array_list<
                                nil::marshalling::field_type<Endianness>,
                                curve_element<nil::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g1_type<>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                                ,
//                              verification_key_type verification_key;
                                nil::marshalling::types::array_list<
                                nil::marshalling::field_type<Endianness>,
                                curve_element<nil::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g2_type<>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                            >
                        >;
                };

                // Marshalling function for KZG params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>>::type
                fill_commitment_params(const typename CommitmentSchemeType::params_type &kzg_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using result_type = typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType>::type;

                    nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    curve_element<nil::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g1_type<>>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    filled_commitment = fill_curve_element_vector<typename CommitmentSchemeType::curve_type::template g1_type<>, Endianness>(kzg_params.commitment_key);

                    nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    curve_element<nil::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g2_type<>>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    filled_verification_key = fill_curve_element_vector<typename CommitmentSchemeType::curve_type::template g2_type<>, Endianness>(kzg_params.verification_key);

                    return result_type(std::make_tuple(
                        filled_commitment,
                        filled_verification_key
                    ));
                }

                // Marshalling function for KZG params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename CommitmentSchemeType::params_type
                make_commitment_params(const typename commitment_params<nil::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>>::type &filled_kzg_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;

                    return result_type(std::make_tuple(
                        make_curve_element_vector<typename CommitmentSchemeType::curve_type::template g1_type<>, Endianness>(std::get<0>(filled_kzg_params.value()).value()),
                        make_curve_element_vector<typename CommitmentSchemeType::curve_type::template g2_type<>, Endianness>(std::get<1>(filled_kzg_params.value()).value())
                    ));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP
