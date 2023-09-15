//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // FOR LPC only because of basic_fri field
                template <typename TTypeBase, typename LPC > 
                struct eval_proof{
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // Evaluation points storage z
                            eval_storage<TTypeBase, typename LPC::field_type>,

                            // One fri proof
                            typename fri_proof<TTypeBase, typename LPC::basic_fri>::type
                        >
                    >;
                };

                template<typename Endianness, typename LPC>
                typename eval_proof<nil::marshalling::field_type<Endianness>, LPC>::type 
                fill_eval_proof( const typename LPC::proof_type &proof ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info = proof.z.get_batch_info();

                    auto filled_z = fill_eval_storage<Endianness, typename LPC::field_type>(proof.z);

                    typename fri_proof<TTypeBase, typename LPC::basic_fri>::type filled_fri_proof = fill_fri_proof<Endianness, typename LPC::basic_fri>(
                        proof.fri_proof, batch_info
                    );

                    return typename eval_proof<TTypeBase, LPC>::type(
                        std::tuple( filled_z, filled_fri_proof)
                    );
                }

                template<typename Endianness, typename LPC>
                typename LPC::proof_type make_eval_proof(const typename eval_proof<nil::marshalling::field_type<Endianness>, LPC>::type &filled_proof){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename LPC::proof_type proof;

                    proof.z = make_eval_storage<Endianness, typename LPC::field_type>(std::get<0>(filled_proof.value()));
                    auto batch_info = proof.z.get_batch_info();
                    proof.fri_proof = make_fri_proof<Endianness, typename LPC::basic_fri>(std::get<1>(filled_proof.value()), batch_info);

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
