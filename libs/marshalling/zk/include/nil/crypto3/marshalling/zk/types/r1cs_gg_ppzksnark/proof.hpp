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

#ifndef CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROOF_HPP
#define CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROOF_HPP

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

#include <nil/crypto3/container/accumulation_vector.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/proof.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/marshalling/zk/types/accumulation_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase,
                         typename ProofType,
                         typename = typename std::enable_if<
                             std::is_same<ProofType,
                                          zk::snark::r1cs_gg_ppzksnark_proof<typename ProofType::curve_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_gg_ppzksnark_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // g_A
                        curve_element<TTypeBase, typename ProofType::curve_type::template g1_type<>>,
                        // g_B
                        curve_element<TTypeBase, typename ProofType::curve_type::template g2_type<>>,
                        // g_C
                        curve_element<TTypeBase, typename ProofType::curve_type::template g1_type<>>>>;

                template<typename ProofType, typename Endianness>
                r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<Endianness>, ProofType>
                    fill_r1cs_gg_ppzksnark_proof(const ProofType &r1cs_gg_ppzksnark_proof_inp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using curve_g1_element_type =
                        curve_element<TTypeBase, typename ProofType::curve_type::template g1_type<>>;

                    using curve_g2_element_type =
                        curve_element<TTypeBase, typename ProofType::curve_type::template g2_type<>>;

                    return r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<Endianness>, ProofType>(
                        std::make_tuple(curve_g1_element_type(r1cs_gg_ppzksnark_proof_inp.g_A),
                                        curve_g2_element_type(r1cs_gg_ppzksnark_proof_inp.g_B),
                                        curve_g1_element_type(r1cs_gg_ppzksnark_proof_inp.g_C)));
                }

                template<typename ProofType, typename Endianness>
                ProofType make_r1cs_gg_ppzksnark_proof(
                    const r1cs_gg_ppzksnark_proof<nil::marshalling::field_type<Endianness>, ProofType>
                        &filled_r1cs_gg_ppzksnark_proof) {

                    return ProofType(std::move(std::get<0>(filled_r1cs_gg_ppzksnark_proof.value()).value()),
                                     std::move(std::get<1>(filled_r1cs_gg_ppzksnark_proof.value()).value()),
                                     std::move(std::get<2>(filled_r1cs_gg_ppzksnark_proof.value()).value()));
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_R1CS_GG_PPZKSNARK_PROOF_HPP
