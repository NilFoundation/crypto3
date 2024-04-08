//---------------------------------------------------------------------------//
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2023 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_KZG_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_KZG_COMMITMENT_HPP

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>

#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/eval_storage.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                /* KZGScheme is like batched_kzg,
                 * commitment is a std::vector<uint8_t>, holding serialized g1 points
                 * */
                template <typename TTypeBase, typename KZGScheme>
                struct commitment<TTypeBase, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme>>> {
                    using type = nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::uint16_t>>
                    >;
                };

                template <typename Endianness, typename KZGScheme>
                typename commitment<nil::marshalling::field_type<Endianness>, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme>>>::type
                fill_commitment(typename KZGScheme::commitment_type commitment) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = typename nil::crypto3::marshalling::types::commitment<TTypeBase, KZGScheme>::type;
                    result_type result;
                    for( auto it = commitment.begin(); it != commitment.end(); it++ ){
                        result.value().push_back(nil::marshalling::types::integral<TTypeBase,uint8_t>(*it));
                    }
                    return result;
                }

                template <typename Endianness, typename KZGScheme>
                typename KZGScheme::commitment_type
                make_commitment(typename commitment<nil::marshalling::field_type<Endianness>, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme>>>::type const& filled_commitment) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename KZGScheme::commitment_type result;
                    for( std::size_t i = 0; i < filled_commitment.value().size(); i++ ){
                        result.push_back(filled_commitment.value()[i].value());
                    }
                    return result;
                }

                /* KZGScheme is like kzg_batched_commitment_v2 */
                template <typename TTypeBase, typename KZGScheme>
                struct eval_proof<TTypeBase, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme> > > {

                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            eval_storage<TTypeBase, typename KZGScheme::eval_storage_type>,
                            curve_element<TTypeBase, typename KZGScheme::single_commitment_type::group_type>,
                            curve_element<TTypeBase, typename KZGScheme::single_commitment_type::group_type>
                        >
                    >;
                };

                template<typename Endianness, typename KZGScheme>
                typename eval_proof<nil::marshalling::field_type<Endianness>, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme>>>::type
                fill_eval_proof( const typename KZGScheme::proof_type &proof, typename KZGScheme::params_type const& params) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info = proof.z.get_batch_info();

                    using curve_marhsalling_type = curve_element<TTypeBase, typename KZGScheme::single_commitment_type::group_type>;

                    auto filled_z = fill_eval_storage<Endianness, typename KZGScheme::eval_storage_type>(proof.z);

                    curve_marhsalling_type filled_pi_1 = curve_marhsalling_type(proof.pi_1);
                    curve_marhsalling_type filled_pi_2 = curve_marhsalling_type(proof.pi_2);

                    return typename eval_proof<TTypeBase, KZGScheme>::type(
                        std::tuple( filled_z, filled_pi_1, filled_pi_2 )
                    );
                }

                template<typename Endianness, typename KZGScheme>
                typename KZGScheme::proof_type
                make_eval_proof(const typename eval_proof<nil::marshalling::field_type<Endianness>, KZGScheme, std::enable_if_t<nil::crypto3::zk::is_kzg<KZGScheme>>>::type &filled_proof) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    typename KZGScheme::proof_type proof;

                    proof.z = make_eval_storage<Endianness, typename KZGScheme::eval_storage_type>(std::get<0>(filled_proof.value()));
                    auto batch_info = proof.z.get_batch_info();
                    proof.pi_1= std::get<1>(filled_proof.value()).value();
                    proof.pi_2= std::get<2>(filled_proof.value()).value();

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_KZG_COMMITMENT_HPP
