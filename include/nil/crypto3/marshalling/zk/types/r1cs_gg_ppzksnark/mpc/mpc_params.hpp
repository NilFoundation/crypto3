//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_MPC_PARAMS_HPP
#define CRYPTO3_MARSHALLING_MPC_PARAMS_HPP

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

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/mpc_generator/mpc_params.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/fast_proving_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename MPCParams,
                         typename = typename std::enable_if<
                             std::is_same<MPCParams,
                                          zk::snark::r1cs_gg_ppzksnark_mpc_params<
                                              typename MPCParams::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_mpc_params = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        r1cs_gg_ppzksnark_fast_proving_key<TTypeBase, typename MPCParams::proving_scheme_type::keypair_type::first_type>,
                        r1cs_gg_ppzksnark_verification_key<TTypeBase, typename MPCParams::proving_scheme_type::keypair_type::second_type>
                    >>;

                template<typename MPCParams, typename Endianness>
                r1cs_gg_ppzksnark_mpc_params<nil::marshalling::field_type<Endianness>, MPCParams>
                    fill_r1cs_gg_ppzksnark_mpc_params(const MPCParams &mpc_params) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    return r1cs_gg_ppzksnark_mpc_params<TTypeBase, MPCParams>(std::make_tuple(
                        std::move(
                            fill_r1cs_gg_ppzksnark_fast_proving_key<typename MPCParams::proving_scheme_type::keypair_type::first_type, Endianness>(
                                mpc_params.keypair.first)),
                        std::move(
                            fill_r1cs_gg_ppzksnark_verification_key<typename MPCParams::proving_scheme_type::keypair_type::second_type, Endianness>(
                                mpc_params.keypair.second))
                        ));
                }

                // template<typename Accumulator, typename Endianness>
                // Accumulator make_r1cs_gg_ppzksnark_fast_proving_key(
                //     const r1cs_gg_ppzksnark_fast_proving_key<nil::marshalling::field_type<Endianness>, Accumulator>
                //         &filled_proving_key) {

                //     return Accumulator(
                //         std::move(
                //             make_fast_curve_element<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<0>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<1>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                //                 std::get<2>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<3>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element<typename Accumulator::curve_type::template g2_type<>, Endianness>(
                //                 std::get<4>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<5>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_knowledge_commitment_vector<nil::crypto3::zk::commitments::knowledge_commitment_vector<
                //                                                  typename Accumulator::curve_type::template g2_type<>,
                //                                                  typename Accumulator::curve_type::template g1_type<>>,
                //                                              Endianness>(std::get<6>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<7>(filled_proving_key.value()))),
                //         std::move(
                //             make_fast_curve_element_vector<typename Accumulator::curve_type::template g1_type<>, Endianness>(
                //                 std::get<8>(filled_proving_key.value()))),
                //         std::move(make_r1cs_constraint_system<typename Accumulator::constraint_system_type, Endianness>(
                //             std::get<9>(filled_proving_key.value()))));
                // }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_MPC_PARAMS_HPP
