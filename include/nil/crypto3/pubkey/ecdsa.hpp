//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_ECDSA_HPP
#define CRYPTO3_PUBKEY_ECDSA_HPP

#include <utility>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            // TODO: add distribution support
            // TODO: review ECDSA implementation and add auxiliary functional provided by the standard
            // TODO: review generator passing
            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType = void,
                     typename = typename std::enable_if<std::is_same<typename CurveType::scalar_field_type::value_type,
                                                                     typename GeneratorType::result_type>::value>::type>
            struct ecdsa {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> self_type;
                typedef CurveType curve_type;
                typedef Padding padding_type;
                typedef GeneratorType generator_type;
                typedef DistributionType distribution_type;

                typedef public_key<self_type> public_key_type;
                typedef private_key<self_type> private_key_type;
            };

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> policy_type;

                typedef typename policy_type::curve_type curve_type;
                typedef typename policy_type::padding_type padding_type;

                typedef padding::encoding_accumulator_set<padding_type> internal_accumulator_type;

                typedef typename curve_type::scalar_field_type scalar_field_type;
                typedef typename scalar_field_type::value_type scalar_field_value_type;
                typedef typename curve_type::g1_type g1_type;
                typedef typename g1_type::value_type g1_value_type;
                typedef typename curve_type::base_field_type::modulus_type base_modulus_type;
                typedef typename scalar_field_type::number_type scalar_number_type;

                typedef g1_value_type public_key_type;
                typedef std::pair<scalar_field_value_type, scalar_field_value_type> signature_type;

                public_key(const public_key_type &key) : pubkey(key) {
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &acc, const InputRange &range) const {
                    encode<padding_type>(range, acc);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) const {
                    encode<padding_type>(first, last, acc);
                }

                inline bool verify(internal_accumulator_type &acc, const signature_type &signature) const {
                    scalar_field_value_type m =
                        padding::accumulators::extract::encode<padding::encoding_policy<padding_type>>(acc);

                    scalar_field_value_type w = signature.second.inversed();
                    g1_value_type X = (m * w) * g1_value_type::one() + (signature.first * w) * pubkey;
                    if (X.is_zero()) {
                        return false;
                    }
                    return signature.first ==
                           scalar_field_value_type(scalar_number_type(
                               static_cast<base_modulus_type>(X.to_affine().X.data), scalar_field_value_type::modulus));
                }

            protected:
                public_key_type pubkey;
            };

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct private_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>>
                : public public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> policy_type;
                typedef public_key<policy_type> base_type;

                typedef typename policy_type::curve_type curve_type;
                typedef typename policy_type::padding_type padding_type;
                typedef typename policy_type::generator_type generator_type;
                typedef typename policy_type::distribution_type distribution_type;

                typedef padding::encoding_accumulator_set<padding_type> internal_accumulator_type;

                typedef typename base_type::scalar_field_value_type scalar_field_value_type;
                typedef typename base_type::g1_value_type g1_value_type;
                typedef typename base_type::base_modulus_type base_modulus_type;
                typedef typename base_type::scalar_number_type scalar_number_type;

                typedef scalar_field_value_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                private_key(const private_key_type &key) : privkey(key), base_type(generate_public_key(key)) {
                }

                static inline public_key_type generate_public_key(const private_key_type &key) {
                    return key * public_key_type::one();
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &acc, const InputRange &range) const {
                    encode<padding_type>(range, acc);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) const {
                    encode<padding_type>(first, last, acc);
                }

                // TODO: review to make blind signing
                // TODO: add support of HMAC based generator (https://datatracker.ietf.org/doc/html/rfc6979)
                // TODO: review passing of generator seed
                inline signature_type sign(internal_accumulator_type &acc) const {
                    generator_type gen;
                    scalar_field_value_type m =
                        padding::accumulators::extract::encode<padding::encoding_policy<padding_type>>(acc);

                    // TODO: review behaviour if k, r or s generation produced zero, maybe return status instead cycled
                    //  generation
                    scalar_field_value_type k;
                    scalar_field_value_type r;
                    scalar_field_value_type s;
                    do {
                        while ((k = gen()).is_zero()) {
                        }
                        // TODO: review converting of kG x-coordinate to r - in case of 2^m order field procedure seems
                        //  not to be trivial
                        r = scalar_field_value_type(scalar_number_type(
                            static_cast<base_modulus_type>((k * g1_value_type::one()).to_affine().X.data),
                            scalar_field_value_type::modulus));
                        s = k.inversed() * (privkey * r + m);
                    } while (r.is_zero() || s.is_zero());

                    return signature_type(r, s);
                }

            protected:
                private_key_type privkey;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_ECDSA_HPP
