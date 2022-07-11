//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_EDDSA_HPP
#define CRYPTO3_PUBKEY_EDDSA_HPP

#include <cstddef>
#include <array>
#include <vector>

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include <nil/crypto3/pkpad/emsa/emsa_raw.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>

#include <nil/crypto3/pubkey/type_traits.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            enum class eddsa_type { basic, ctx, ph };

            template<eddsa_type, typename Params, typename = void>
            struct eddsa_policy;

            template<typename Params>
            struct eddsa_policy<eddsa_type::basic, Params> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> domain_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa_raw<std::uint8_t> padding_policy;

                static inline domain_type domain() {
                    return {};
                }
            };

            template<typename Params>
            struct eddsa_policy<
                eddsa_type::ctx, Params,
                typename std::enable_if<
                    is_eddsa_params<Params>::value &&
                    std::is_same<std::uint8_t, typename std::iterator_traits<typename Params::context_type::iterator>::
                                                   value_type>::value>::type> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> domain_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa_raw<std::uint8_t> padding_policy;

                static constexpr std::uint8_t phflag = 0;

                static inline domain_type domain() {
                    std::size_t context_len =
                        std::distance(std::cbegin(params_type::context), std::cend(params_type::context));
                    BOOST_ASSERT(0 < context_len && context_len <= 255);

                    std::string dom_prefix = "SigEd25519 no Ed25519 collisions";
                    domain_type dom(std::cbegin(dom_prefix), std::cend(dom_prefix));
                    dom.push_back(phflag);
                    dom.push_back(static_cast<std::uint8_t>(context_len));
                    std::copy(std::cbegin(params_type::context), std::cend(params_type::context),
                              std::back_inserter(dom));

                    return dom;
                }
            };

            template<typename Params>
            struct eddsa_policy<
                eddsa_type::ph, Params,
                typename std::enable_if<
                    is_eddsa_params<Params>::value &&
                    std::is_same<std::uint8_t, typename std::iterator_traits<typename Params::context_type::iterator>::
                                                   value_type>::value>::type> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> domain_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa1<typename hash_type::digest_type, hash_type> padding_policy;

                static constexpr std::uint8_t phflag = 1;

                static inline domain_type domain() {
                    std::size_t context_len =
                        std::distance(std::cbegin(params_type::context), std::cend(params_type::context));
                    BOOST_ASSERT(0 <= context_len && context_len <= 255);

                    std::string dom_prefix = "SigEd25519 no Ed25519 collisions";
                    domain_type dom(std::cbegin(dom_prefix), std::cend(dom_prefix));
                    dom.push_back(phflag);
                    dom.push_back(static_cast<std::uint8_t>(context_len));
                    std::copy(std::cbegin(params_type::context), std::cend(params_type::context),
                              std::back_inserter(dom));

                    return dom;
                }
            };

            template<typename CurveGroup, eddsa_type eddsa_variant, typename Params>
            struct eddsa;

            template<typename Coordinates, eddsa_type eddsa_variant, typename Params>
            struct eddsa<
                typename algebra::curves::ed25519::g1_type<Coordinates, algebra::curves::forms::twisted_edwards>,
                eddsa_variant, Params> {
                typedef
                    typename algebra::curves::ed25519::g1_type<Coordinates, algebra::curves::forms::twisted_edwards>
                        group_type;
                typedef eddsa_policy<eddsa_variant, Params> policy_type;
            };

            template<typename CurveGroup, eddsa_type eddsa_variant, typename Params>
            struct public_key<eddsa<CurveGroup, eddsa_variant, Params>> {
                typedef eddsa<CurveGroup, eddsa_variant, Params> scheme_type;
                typedef typename scheme_type::policy_type policy_type;
                typedef typename policy_type::hash_type hash_type;
                typedef typename policy_type::padding_policy padding_policy;
                typedef padding::encoding_accumulator_set<padding_policy> internal_accumulator_type;

                typedef typename scheme_type::group_type group_type;
                typedef typename group_type::value_type group_value_type;
                typedef typename group_type::curve_type::base_field_type base_field_type;
                typedef typename base_field_type::value_type base_field_value_type;
                typedef typename base_field_type::integral_type base_integral_type;
                typedef typename group_type::curve_type::scalar_field_type scalar_field_type;
                typedef typename scalar_field_type::value_type scalar_field_value_type;
                typedef typename scalar_field_type::integral_type scalar_integral_type;

                typedef nil::marshalling::option::little_endian endianness;
                typedef nil::crypto3::marshalling::types::curve_element<nil::marshalling::field_type<endianness>,
                                                                        group_type>
                    marshalling_group_value_type;
                typedef nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<endianness>,
                                                                        scalar_field_value_type>
                    marshalling_scalar_field_value_type;
                typedef nil::crypto3::marshalling::types::integral<nil::marshalling::field_type<endianness>,
                                                                   base_integral_type>
                    marshalling_base_integral_type;
                typedef nil::crypto3::marshalling::types::integral<nil::marshalling::field_type<endianness>,
                                                                   nil::crypto3::multiprecision::uint512_t>
                    marshalling_uint512_t_type;

                constexpr static const std::size_t public_key_bits = base_field_type::modulus_bits;
                static_assert(32 * std::numeric_limits<std::uint8_t>::digits - 1 == public_key_bits,
                              "wrong octet length of public key");
                typedef static_digest<public_key_bits +
                                      (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 :
                                                                                                                   0)>
                    public_key_type;

                constexpr static const std::size_t signature_bits = 64 * std::numeric_limits<std::uint8_t>::digits;
                typedef static_digest<signature_bits> signature_type;

                public_key() = delete;
                public_key(const public_key_type &key) : pubkey_point(read_pubkey(key)), pubkey(key) {
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

                // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7
                inline bool verify(internal_accumulator_type &acc, const signature_type &signature) const {
                    // 1.
                    marshalling_group_value_type marshalling_group_value_1;
                    auto R_iter_1 = std::cbegin(signature);
                    if (marshalling_group_value_1.read(R_iter_1, marshalling_group_value_type::bit_length()) !=
                        nil::marshalling::status_type::success) {
                        return false;
                    }
                    group_value_type R = marshalling_group_value_1.value();

                    marshalling_scalar_field_value_type marshalling_scalar_field_value_1;
                    auto S_iter_1 = std::cbegin(signature) +
                                    public_key_bits / std::numeric_limits<std::uint8_t>::digits +
                                    (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 : 0);
                    if (marshalling_scalar_field_value_1.read(S_iter_1,
                                                              marshalling_scalar_field_value_type::bit_length()) !=
                        nil::marshalling::status_type::success) {
                        return false;
                    }
                    scalar_field_value_type S = marshalling_scalar_field_value_1.value();

                    // 2.
                    auto ph_m = padding::accumulators::extract::encode<padding::encoding_policy<padding_policy>>(acc);
                    accumulator_set<hash_type> hash_acc_2;
                    hash<hash_type>(policy_type::domain(), hash_acc_2);
                    hash<hash_type>(
                        std::cbegin(signature),
                        std::cbegin(signature) + public_key_bits / std::numeric_limits<std::uint8_t>::digits +
                            (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 : 0),
                        hash_acc_2);
                    hash<hash_type>(this->pubkey, hash_acc_2);
                    hash<hash_type>(ph_m, hash_acc_2);
                    typename hash_type::digest_type h_2 =
                        nil::crypto3::accumulators::extract::hash<hash_type>(hash_acc_2);
                    marshalling_uint512_t_type marshalling_uint512_t_2;
                    auto h_2_iter = std::cbegin(h_2);

                    if (marshalling_uint512_t_2.read(h_2_iter, hash_type::digest_bits) !=
                        nil::marshalling::status_type::success) {
                        return false;
                    }
                    multiprecision::uint512_t k = marshalling_uint512_t_2.value();
                    scalar_field_value_type k_reduced(k);

                    // 3.
                    return (S * group_value_type::one()) == (R + k_reduced * this->pubkey_point);
                }

                inline public_key_type public_key_data() const {
                    return pubkey;
                }

            // protected:
                static inline group_value_type read_pubkey(const public_key_type &pubkey) {
                    marshalling_group_value_type marshalling_group_value_1;
                    auto pubkey_iter = std::cbegin(pubkey);
                    // TODO: process status
                    nil::marshalling::status_type status =
                        marshalling_group_value_1.read(pubkey_iter, marshalling_group_value_type::bit_length());
                    return marshalling_group_value_1.value();
                }

                group_value_type pubkey_point;
                public_key_type pubkey;
            };

            template<typename CurveGroup, eddsa_type eddsa_variant, typename Params>
            struct private_key<eddsa<CurveGroup, eddsa_variant, Params>>
                : public public_key<eddsa<CurveGroup, eddsa_variant, Params>> {
                typedef eddsa<CurveGroup, eddsa_variant, Params> scheme_type;
                typedef public_key<scheme_type> scheme_public_key_type;

                typedef typename scheme_public_key_type::policy_type policy_type;
                typedef typename scheme_public_key_type::hash_type hash_type;
                typedef typename scheme_public_key_type::padding_policy padding_policy;
                typedef typename scheme_public_key_type::internal_accumulator_type internal_accumulator_type;

                typedef typename scheme_public_key_type::group_value_type group_value_type;
                typedef typename scheme_public_key_type::scalar_field_type scalar_field_type;
                typedef typename scheme_public_key_type::scalar_field_value_type scalar_field_value_type;
                typedef typename scheme_public_key_type::scalar_integral_type scalar_integral_type;
                typedef typename scheme_public_key_type::base_field_type base_field_type;
                typedef typename scheme_public_key_type::base_integral_type base_integral_type;

                typedef typename scheme_public_key_type::endianness endianness;
                typedef typename scheme_public_key_type::marshalling_group_value_type marshalling_group_value_type;
                typedef typename scheme_public_key_type::marshalling_scalar_field_value_type
                    marshalling_scalar_field_value_type;
                typedef typename scheme_public_key_type::marshalling_base_integral_type marshalling_base_integral_type;
                typedef typename scheme_public_key_type::marshalling_uint512_t_type marshalling_uint512_t_type;

                constexpr static const std::size_t private_key_bits = base_field_type::modulus_bits;
                static_assert(32 * std::numeric_limits<std::uint8_t>::digits - 1 == private_key_bits,
                              "wrong octet length of private key");
                typedef static_digest<private_key_bits +
                                      (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 :
                                                                                                                   0)>
                    private_key_type;

                constexpr static const std::size_t public_key_bits = scheme_public_key_type::public_key_bits;
                typedef typename scheme_public_key_type::public_key_type public_key_type;

                constexpr static const std::size_t signature_bits = scheme_public_key_type::signature_bits;
                typedef typename scheme_public_key_type::signature_type signature_type;

                private_key() = delete;
                private_key(const private_key_type &key) :
                    privkey(key), h_privkey(hash<hash_type>(key)), s_reduced(construct_scalar(h_privkey)),
                    scheme_public_key_type(generate_public_key(key)) {
                }

                // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
                static inline public_key_type generate_public_key(const private_key_type &key) {
                    // 1.
                    typename hash_type::digest_type h = hash<hash_type>(key);

                    base_integral_type s = construct_scalar(h);

                    // 3.
                    group_value_type sB = scalar_field_value_type(s) * group_value_type::one();

                    // 4.
                    marshalling_group_value_type marshalling_group_value(sB);
                    public_key_type public_key;
                    auto write_iter = std::begin(public_key);
                    // TODO: process status
                    if (marshalling_group_value.write(write_iter, public_key_bits) !=
                        nil::marshalling::status_type::success) {
                        return {};
                    }

                    return public_key;
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

                // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
                inline signature_type sign(internal_accumulator_type &acc) const {
                    // 2.
                    auto ph_m = padding::accumulators::extract::encode<padding::encoding_policy<padding_policy>>(acc);
                    accumulator_set<hash_type> hash_acc_2;
                    hash<hash_type>(policy_type::domain(), hash_acc_2);
                    hash<hash_type>(
                        std::cbegin(h_privkey) + private_key_bits / std::numeric_limits<std::uint8_t>::digits +
                            (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 : 0),
                        std::cend(h_privkey), hash_acc_2);
                    hash<hash_type>(ph_m, hash_acc_2);
                    typename hash_type::digest_type h_2 =
                        nil::crypto3::accumulators::extract::hash<hash_type>(hash_acc_2);
                    marshalling_uint512_t_type marshalling_uint512_t_2;
                    auto h_2_it = std::cbegin(h_2);
                    // TODO: process status
                    if (marshalling_uint512_t_2.read(h_2_it, hash_type::digest_bits) !=
                        nil::marshalling::status_type::success) {
                        return {};
                    }
                    nil::crypto3::multiprecision::uint512_t r = marshalling_uint512_t_2.value();
                    scalar_field_value_type r_reduced(r);

                    // 3.
                    group_value_type rB = r_reduced * group_value_type::one();
                    marshalling_group_value_type marshalling_group_value(rB);
                    signature_type signature;
                    auto sig_iter_3 = std::begin(signature);
                    // TODO: process status
                    if (marshalling_group_value.write(sig_iter_3, public_key_bits) !=
                        nil::marshalling::status_type::success) {
                        return {};
                    }

                    // 4.
                    accumulator_set<hash_type> hash_acc_4;
                    hash<hash_type>(policy_type::domain(), hash_acc_4);
                    hash<hash_type>(
                        std::cbegin(signature),
                        std::cbegin(signature) + public_key_bits / std::numeric_limits<std::uint8_t>::digits +
                            (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 : 0),
                        hash_acc_4);
                    hash<hash_type>(this->pubkey, hash_acc_4);
                    hash<hash_type>(ph_m, hash_acc_4);
                    typename hash_type::digest_type h_4 =
                        nil::crypto3::accumulators::extract::hash<hash_type>(hash_acc_4);
                    marshalling_uint512_t_type marshalling_uint512_t_4;
                    auto h_4_it = std::cbegin(h_4);
                    if (marshalling_uint512_t_4.read(h_4_it, hash_type::digest_bits) !=
                        nil::marshalling::status_type::success) {
                        return {};
                    }
                    nil::crypto3::multiprecision::uint512_t k = marshalling_uint512_t_4.value();
                    scalar_field_value_type k_reduced(k);

                    // 5.
                    scalar_field_value_type S = r_reduced + k_reduced * s_reduced;

                    // 6.
                    marshalling_scalar_field_value_type marshalling_scalar_field_value_6(S);
                    std::size_t offset_6 =
                        public_key_bits / std::numeric_limits<std::uint8_t>::digits +
                        (base_field_type::modulus_bits % std::numeric_limits<std::uint8_t>::digits ? 1 : 0);
                    auto sig_iter_6 = std::begin(signature) + offset_6;
                    std::size_t remaining_bytes_6 = signature.size() - offset_6;
                    if (marshalling_scalar_field_value_6.write(sig_iter_6, remaining_bytes_6) !=
                        nil::marshalling::status_type::success) {
                        return {};
                    }

                    return signature;
                }

            // protected:
                // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
                static inline base_integral_type construct_scalar(const typename hash_type::digest_type &h) {
                    // 3.
                    marshalling_base_integral_type marshalling_base_integral;
                    auto h_it = std::cbegin(h);
                    marshalling_base_integral.read(h_it, private_key_bits);
                    base_integral_type s = marshalling_base_integral.value();

                    // 2.
                    s &= ((base_integral_type(1) << 254) - 8);
                    s |= (base_integral_type(1) << 254);

                    return s;
                }

                // TODO: refactor eddsa private key internal fields
                private_key_type privkey;
                typename hash_type::digest_type h_privkey;
                scalar_field_value_type s_reduced;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_EDDSA_HPP
