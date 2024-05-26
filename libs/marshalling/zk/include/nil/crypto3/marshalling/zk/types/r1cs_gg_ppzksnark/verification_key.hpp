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

#ifndef CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_VERIFICATION_KEY_HPP
#define CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_VERIFICATION_KEY_HPP

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
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>

#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/accumulation_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename VerificationKey,
                         typename =
                             typename std::enable_if<std::is_same<VerificationKey,
                                                                  zk::snark::r1cs_gg_ppzksnark_verification_key<
                                                                      typename VerificationKey::curve_type>>::value,
                                                     bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_verification_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // alpha_g1_beta_g2
                        field_element<TTypeBase, typename VerificationKey::curve_type::gt_type::value_type>,
                        // gamma_g2
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>,
                        // delta_g2
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>,
                        // gamma_ABC_g1
                        accumulation_vector<
                            TTypeBase,
                            container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>>>>;

                template<typename VerificationKey, typename Endianness>
                r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<Endianness>, VerificationKey>
                    fill_r1cs_gg_ppzksnark_verification_key(
                        const VerificationKey &r1cs_gg_ppzksnark_verification_key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using field_gt_element_type =
                        field_element<TTypeBase, typename VerificationKey::curve_type::gt_type::value_type>;
                    using curve_g2_element_type =
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>;
                    using accumulation_vector_type = accumulation_vector<
                        TTypeBase,
                        container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>>;

                    field_gt_element_type filled_alpha_g1_beta_g2(
                        r1cs_gg_ppzksnark_verification_key_inp.alpha_g1_beta_g2);

                    curve_g2_element_type filled_gamma_g2 =
                        curve_g2_element_type(r1cs_gg_ppzksnark_verification_key_inp.gamma_g2);

                    curve_g2_element_type filled_delta_g2 =
                        curve_g2_element_type(r1cs_gg_ppzksnark_verification_key_inp.delta_g2);

                    accumulation_vector_type filled_gamma_ABC_g1 = fill_accumulation_vector<
                        container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>,
                        Endianness>(r1cs_gg_ppzksnark_verification_key_inp.gamma_ABC_g1);

                    return r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<Endianness>,
                                                              VerificationKey>(std::make_tuple(
                        filled_alpha_g1_beta_g2, filled_gamma_g2, filled_delta_g2, filled_gamma_ABC_g1));
                }

                template<typename VerificationKey, typename Endianness>
                VerificationKey make_r1cs_gg_ppzksnark_verification_key(
                    const r1cs_gg_ppzksnark_verification_key<nil::marshalling::field_type<Endianness>, VerificationKey>
                        &filled_r1cs_gg_ppzksnark_verification_key) {

                    return VerificationKey(
                        std::move(std::get<0>(filled_r1cs_gg_ppzksnark_verification_key.value()).value()),
                        std::move(std::get<1>(filled_r1cs_gg_ppzksnark_verification_key.value()).value()),
                        std::move(std::get<2>(filled_r1cs_gg_ppzksnark_verification_key.value()).value()),
                        std::move(
                            make_accumulation_vector<container::accumulation_vector<
                                                         typename VerificationKey::curve_type::template g1_type<>>,
                                                     Endianness>(
                                std::get<3>(filled_r1cs_gg_ppzksnark_verification_key.value()))));
                }

                template<typename TTypeBase,
                         typename VerificationKey,
                         typename = typename std::enable_if<
                             std::is_same<VerificationKey,
                                          zk::snark::r1cs_gg_ppzksnark_extended_verification_key<
                                              typename VerificationKey::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_extended_verification_key = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // alpha_g1_beta_g2
                        field_element<TTypeBase, typename VerificationKey::curve_type::gt_type::value_type>,
                        // gamma_g2
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>,
                        // delta_g2
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>,
                        // delta_g1
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g1_type<>>,
                        // gamma_g1
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g1_type<>>,
                        // gamma_ABC_g1
                        accumulation_vector<
                            TTypeBase,
                            container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>>>>;

                template<typename VerificationKey, typename Endianness>
                r1cs_gg_ppzksnark_extended_verification_key<nil::marshalling::field_type<Endianness>, VerificationKey>
                    fill_r1cs_gg_ppzksnark_verification_key(
                        const VerificationKey &r1cs_gg_ppzksnark_verification_key_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using field_gt_element_type =
                        field_element<TTypeBase, typename VerificationKey::curve_type::gt_type::value_type>;
                    using curve_g1_element_type =
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g1_type<>>;
                    using curve_g2_element_type =
                        curve_element<TTypeBase, typename VerificationKey::curve_type::template g2_type<>>;
                    using accumulation_vector_type = accumulation_vector<
                        TTypeBase,
                        container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>>;

                    field_gt_element_type filled_alpha_g1_beta_g2(
                        r1cs_gg_ppzksnark_verification_key_inp.alpha_g1_beta_g2);

                    curve_g2_element_type filled_gamma_g2 =
                        curve_g2_element_type(r1cs_gg_ppzksnark_verification_key_inp.gamma_g2);

                    curve_g2_element_type filled_delta_g2 =
                        curve_g2_element_type(r1cs_gg_ppzksnark_verification_key_inp.delta_g2);

                    curve_g1_element_type filled_delta_g1 =
                        curve_g1_element_type(r1cs_gg_ppzksnark_verification_key_inp.delta_g1);

                    accumulation_vector_type filled_gamma_ABC_g1 = fill_accumulation_vector<
                        container::accumulation_vector<typename VerificationKey::curve_type::template g1_type<>>,
                        Endianness>(r1cs_gg_ppzksnark_verification_key_inp.gamma_ABC_g1);

                    curve_g1_element_type filled_gamma_g1 =
                        curve_g1_element_type(r1cs_gg_ppzksnark_verification_key_inp.gamma_g1);

                    return r1cs_gg_ppzksnark_extended_verification_key<nil::marshalling::field_type<Endianness>,
                                                                       VerificationKey>(
                        std::make_tuple(filled_alpha_g1_beta_g2,
                                        filled_gamma_g2,
                                        filled_delta_g2,
                                        filled_delta_g1,
                                        filled_gamma_g1,
                                        filled_gamma_ABC_g1));
                }

                template<typename VerificationKey, typename Endianness>
                VerificationKey make_r1cs_gg_ppzksnark_verification_key(
                    const r1cs_gg_ppzksnark_extended_verification_key<nil::marshalling::field_type<Endianness>,
                                                                      VerificationKey>
                        &filled_r1cs_gg_ppzksnark_extended_verification_key) {

                    return VerificationKey(
                        std::move(std::get<0>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()).value()),
                        std::move(std::get<1>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()).value()),
                        std::move(std::get<2>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()).value()),
                        std::move(std::get<3>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()).value()),
                        std::move(
                            make_accumulation_vector<container::accumulation_vector<
                                                         typename VerificationKey::curve_type::template g1_type<>>,
                                                     Endianness>(
                                std::get<5>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()))),
                        std::move(std::get<4>(filled_r1cs_gg_ppzksnark_extended_verification_key.value()).value()));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_VERIFICATION_KEY_HPP
