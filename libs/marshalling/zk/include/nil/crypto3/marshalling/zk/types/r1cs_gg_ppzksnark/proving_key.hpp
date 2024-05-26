//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROVING_KEY_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/tag.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/proving_key.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/accumulation_vector.hpp>
#include <nil/crypto3/marshalling/zk/types/sparse_vector.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename ProvingKey,
                         typename = typename std::enable_if<
                             std::is_same<ProvingKey,
                                          zk::snark::r1cs_gg_ppzksnark_proving_key<
                                              typename ProvingKey::curve_type,
                                              typename ProvingKey::constraint_system_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_proving_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // alpha_g1
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                        // beta_g1
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                        // beta_g2
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g2_type<>>,
                        // delta_g1
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                        // delta_g2
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g2_type<>>,
                        // A_query
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // B_query
                        knowledge_commitment_sparse_vector<TTypeBase,
                                                           nil::crypto3::zk::commitments::knowledge_commitment_vector<
                                                               typename ProvingKey::curve_type::template g2_type<>,
                                                               typename ProvingKey::curve_type::template g1_type<>>>,
                        // H_query
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // L_query
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // constraint_system
                        r1cs_constraint_system<TTypeBase, typename ProvingKey::constraint_system_type>>>;

                template<typename ProvingKey, typename Endianness>
                r1cs_gg_ppzksnark_proving_key<nil::marshalling::field_type<Endianness>, ProvingKey>
                    fill_r1cs_gg_ppzksnark_proving_key(const ProvingKey &proving_key) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using curve_g1_element_type =
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g1_type<>>;
                    using curve_g2_element_type =
                        curve_element<TTypeBase, typename ProvingKey::curve_type::template g2_type<>>;

                    return r1cs_gg_ppzksnark_proving_key<TTypeBase, ProvingKey>(std::make_tuple(
                        std::move(curve_g1_element_type(proving_key.alpha_g1)),
                        std::move(curve_g1_element_type(proving_key.beta_g1)),
                        std::move(curve_g2_element_type(proving_key.beta_g2)),
                        std::move(curve_g1_element_type(proving_key.delta_g1)),
                        std::move(curve_g2_element_type(proving_key.delta_g2)),
                        std::move(
                            fill_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                proving_key.A_query)),
                        std::move(fill_knowledge_commitment_sparse_vector<
                                  nil::crypto3::zk::commitments::knowledge_commitment_vector<
                                      typename ProvingKey::curve_type::template g2_type<>,
                                      typename ProvingKey::curve_type::template g1_type<>>,
                                  Endianness>(proving_key.B_query)),
                        std::move(
                            fill_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                proving_key.H_query)),
                        std::move(
                            fill_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                proving_key.L_query)),
                        std::move(fill_r1cs_constraint_system<typename ProvingKey::constraint_system_type, Endianness>(
                            proving_key.constraint_system))));
                }

                template<typename ProvingKey, typename Endianness>
                ProvingKey make_r1cs_gg_ppzksnark_proving_key(
                    const r1cs_gg_ppzksnark_proving_key<nil::marshalling::field_type<Endianness>, ProvingKey>
                        &filled_proving_key) {

                    return ProvingKey(
                        std::move(std::get<0>(filled_proving_key.value()).value()),
                        std::move(std::get<1>(filled_proving_key.value()).value()),
                        std::move(std::get<2>(filled_proving_key.value()).value()),
                        std::move(std::get<3>(filled_proving_key.value()).value()),
                        std::move(std::get<4>(filled_proving_key.value()).value()),
                        std::move(
                            make_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                std::get<5>(filled_proving_key.value()))),
                        std::move(
                            make_knowledge_commitment_vector<nil::crypto3::zk::commitments::knowledge_commitment_vector<
                                                                 typename ProvingKey::curve_type::template g2_type<>,
                                                                 typename ProvingKey::curve_type::template g1_type<>>,
                                                             Endianness>(std::get<6>(filled_proving_key.value()))),
                        std::move(
                            make_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                std::get<7>(filled_proving_key.value()))),
                        std::move(
                            make_curve_element_vector<typename ProvingKey::curve_type::template g1_type<>, Endianness>(
                                std::get<8>(filled_proving_key.value()))),
                        std::move(make_r1cs_constraint_system<typename ProvingKey::constraint_system_type, Endianness>(
                            std::get<9>(filled_proving_key.value()))));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROVING_KEY_HPP
