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

#include <nil/crypto3/random/rfc6979.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            // TODO: add distribution support
            // TODO: review ECDSA implementation and add auxiliary functional provided by the standard
            // TODO: review generator passing
            template<typename CurveType,
                     typename Padding,
                     typename GeneratorType,
                     typename DistributionType = void,
                     typename = typename std::enable_if<std::is_same<typename CurveType::scalar_field_type::value_type,
                                                                     typename GeneratorType::result_type>::value>::type>
            struct ecdsa {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> self_type;
                typedef CurveType curve_type;
                typedef Padding padding_policy;
                typedef GeneratorType generator_type;
                typedef DistributionType distribution_type;
                typedef typename Padding::hash_type hash_type;

                typedef public_key<self_type> public_key_type;
                typedef private_key<self_type> private_key_type;
            };

            template<typename CurveType,
                     typename Padding,
                     typename GeneratorResultType,
                     typename GeneratorHash,
                     typename DistributionType>
            struct ecdsa<CurveType,
                         Padding,
                         random::rfc6979<GeneratorResultType, GeneratorHash>,
                         DistributionType,
                         typename std::enable_if<std::is_same<typename Padding::hash_type, GeneratorHash>::value &&
                                                 std::is_same<typename CurveType::scalar_field_type::value_type,
                                                              GeneratorResultType>::value>::type> {
                typedef random::rfc6979<GeneratorResultType, GeneratorHash> generator_type;
                typedef ecdsa<CurveType, Padding, generator_type, DistributionType> self_type;
                typedef CurveType curve_type;
                typedef Padding padding_policy;
                typedef DistributionType distribution_type;
                typedef typename Padding::hash_type hash_type;

                typedef public_key<self_type> public_key_type;
                typedef private_key<self_type> private_key_type;
            };

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> policy_type;

                typedef typename policy_type::curve_type curve_type;
                typedef typename policy_type::padding_policy padding_policy;

                typedef padding::encoding_accumulator_set<padding_policy> internal_accumulator_type;

                typedef typename curve_type::scalar_field_type scalar_field_type;
                typedef typename scalar_field_type::value_type scalar_field_value_type;
                typedef typename curve_type::template g1_type<> g1_type;
                typedef typename g1_type::value_type g1_value_type;
                typedef typename curve_type::base_field_type::integral_type base_integral_type;
                typedef typename scalar_field_type::modular_type scalar_modular_type;

                typedef g1_value_type public_key_type;
                typedef std::pair<scalar_field_value_type, scalar_field_value_type> signature_type;

                public_key(const public_key_type &key) : pubkey(key) {
                }

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &acc, const InputRange &range) const {
                    encode<padding_policy>(range, acc);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) const {
                    encode<padding_policy>(first, last, acc);
                }

                inline bool verify(internal_accumulator_type &acc, const signature_type &signature) const {
                    scalar_field_value_type encoded_m =
                        padding::accumulators::extract::encode<padding::encoding_policy<padding_policy>>(acc);

                    scalar_field_value_type w = signature.second.inversed();
                    g1_value_type X = (encoded_m * w) * g1_value_type::one() + (signature.first * w) * pubkey;
                    if (X.is_zero()) {
                        return false;
                    }
                    return signature.first == scalar_field_value_type(scalar_modular_type(
                                                  static_cast<base_integral_type>(X.to_affine().X.data),
                                                  scalar_field_value_type::modulus));
                }

                inline public_key_type pubkey_data() const {
                    return pubkey;
                }

            protected:
                public_key_type pubkey;
            };

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct private_key<
                ecdsa<CurveType, Padding, GeneratorType, DistributionType>,
                typename std::enable_if<!std::is_same<
                    GeneratorType,
                    random::rfc6979<typename CurveType::scalar_field_type::value_type,
                                    typename ecdsa<CurveType, Padding, GeneratorType, DistributionType>::hash_type>>::
                                            value>::type>
                : public public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> policy_type;
                typedef public_key<policy_type> base_type;

                typedef typename policy_type::curve_type curve_type;
                typedef typename policy_type::padding_policy padding_policy;
                typedef typename policy_type::generator_type generator_type;
                typedef typename policy_type::distribution_type distribution_type;
                typedef typename policy_type::hash_type hash_type;

                typedef padding::encoding_accumulator_set<padding_policy> internal_accumulator_type;

                typedef typename base_type::scalar_field_value_type scalar_field_value_type;
                typedef typename base_type::g1_value_type g1_value_type;
                typedef typename base_type::base_integral_type base_integral_type;
                typedef typename base_type::scalar_modular_type scalar_modular_type;

                typedef scalar_field_value_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                private_key(const private_key_type &key) : privkey(key), base_type(generate_public_key(key)) {
                }

                static inline public_key_type generate_public_key(const private_key_type &key) {
                    return key * public_key_type::one();
                }

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &acc, const InputRange &range) const {
                    encode<padding_policy>(range, acc);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) const {
                    encode<padding_policy>(first, last, acc);
                }

                // TODO: review to make blind signing
                // TODO: add support of HMAC based generator (https://datatracker.ietf.org/doc/html/rfc6979)
                // TODO: review passing of generator seed
                inline signature_type sign(internal_accumulator_type &acc) const {
                    generator_type gen;
                    scalar_field_value_type encoded_m =
                        padding::accumulators::extract::encode<padding::encoding_policy<padding_policy>>(acc);

                    // TODO: review behaviour if k, r or s generation produced zero, maybe return status instead cycled
                    //  generation
                    scalar_field_value_type k;
                    scalar_field_value_type r;
                    scalar_field_value_type s;
                    do {
                        while ((k = gen()).is_zero()) {
                        }
                        // TODO: review converting of kG x-coordinate to r - in case of 2^n order (binary) fields
                        //  procedure seems not to be trivial
                        r = scalar_field_value_type(scalar_modular_type(
                            static_cast<base_integral_type>((k * g1_value_type::one()).to_affine().X.data),
                            scalar_field_value_type::modulus));
                        s = k.inversed() * (privkey * r + encoded_m);
                    } while (r.is_zero() || s.is_zero());

                    return signature_type(r, s);
                }

            protected:
                private_key_type privkey;
            };

            template<typename CurveType, typename Padding, typename GeneratorType, typename DistributionType>
            struct private_key<
                ecdsa<CurveType, Padding, GeneratorType, DistributionType>,
                typename std::enable_if<std::is_same<
                    GeneratorType,
                    random::rfc6979<typename CurveType::scalar_field_type::value_type,
                                    typename ecdsa<CurveType, Padding, GeneratorType, DistributionType>::hash_type>>::
                                            value>::type>
                : public public_key<ecdsa<CurveType, Padding, GeneratorType, DistributionType>> {
                typedef ecdsa<CurveType, Padding, GeneratorType, DistributionType> policy_type;
                typedef public_key<policy_type> base_type;

                typedef typename policy_type::curve_type curve_type;
                typedef typename policy_type::padding_policy padding_policy;
                typedef typename policy_type::generator_type generator_type;
                typedef typename policy_type::distribution_type distribution_type;
                typedef typename policy_type::hash_type hash_type;

                typedef std::pair<accumulator_set<hash_type>, padding::encoding_accumulator_set<padding_policy>>
                    internal_accumulator_type;

                typedef typename base_type::scalar_field_value_type scalar_field_value_type;
                typedef typename base_type::g1_value_type g1_value_type;
                typedef typename base_type::base_integral_type base_integral_type;
                typedef typename base_type::scalar_modular_type scalar_modular_type;

                typedef scalar_field_value_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;

                private_key(const private_key_type &key) : privkey(key), base_type(generate_public_key(key)) {
                }

                static inline public_key_type generate_public_key(const private_key_type &key) {
                    return key * public_key_type::one();
                }

                static inline void init_accumulator(internal_accumulator_type &acc) {
                }

                template<typename InputRange>
                inline void update(internal_accumulator_type &acc, const InputRange &range) const {
                    hash<hash_type>(range, acc.first);
                    encode<padding_policy>(range, acc.second);
                }

                template<typename InputIterator>
                inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) const {
                    hash<hash_type>(first, last, acc.first);
                    encode<padding_policy>(first, last, acc.second);
                }

                inline signature_type sign(internal_accumulator_type &acc) const {
                    scalar_field_value_type encoded_m =
                        padding::accumulators::extract::encode<padding::encoding_policy<padding_policy>>(acc.second);

                    auto h = ::nil::crypto3::accumulators::extract::hash<hash_type>(acc.first);
                    generator_type gen(privkey, h);

                    // TODO: review behaviour if k, r or s generation produced zero, maybe return status instead cycled
                    //  generation
                    scalar_field_value_type k;
                    scalar_field_value_type r;
                    scalar_field_value_type s;
                    do {
                        while ((k = gen()).is_zero()) {
                        }
                        // TODO: review converting of kG x-coordinate to r - in case of 2^n order (binary) fields
                        //  procedure seems not to be trivial
                        r = scalar_field_value_type(scalar_modular_type(
                            static_cast<base_integral_type>((k * g1_value_type::one()).to_affine().X.data),
                            scalar_field_value_type::modulus));
                        s = (privkey * r + encoded_m) / k;
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
