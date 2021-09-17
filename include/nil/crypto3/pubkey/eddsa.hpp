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

#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/pkpad/algorithms/encode.hpp>
#include <nil/crypto3/pkpad/emsa/emsa1.hpp>
#include <nil/crypto3/pkpad/emsa/emsa_raw.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

#include <nil/crypto3/pubkey/type_traits.hpp>

#include <nil/crypto3/marshalling/types/integral.hpp>
#include <nil/crypto3/marshalling/types/algebra/field_element.hpp>
#include <nil/crypto3/marshalling/types/algebra/curve_element.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            enum class EddsaVariant { basic, ph, ctx };

            template<
                EddsaVariant, typename Params,
                typename = typename std::enable_if<
                    is_eddsa_params<Params>::value &&
                    std::is_same<std::uint8_t, typename std::iterator_traits<
                                                   typename Params::context_type::iterator>::value_type>::value>::type>
            struct eddsa_policy;

            template<typename Params>
            struct eddsa_policy<EddsaVariant::basic, Params, void> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> dom_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa_raw<std::uint8_t> padding_policy;

                static inline dom_type get_dom() {
                    return dom_type {};
                }
            };

            template<typename Params>
            struct eddsa_policy<EddsaVariant::ph, Params> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> dom_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa_raw<std::uint8_t> padding_policy;

                static constexpr std::uint8_t phflag = 0;

                static inline dom_type get_dom() {
                    std::size_t context_len =
                        std::distance(std::cbegin(params_type::context), std::cend(params_type::context));
                    assert(0 < context_len && context_len <= 255);

                    std::string dom_prefix = "SigEd25519 no Ed25519 collisions";
                    dom_type dom(std::cbegin(dom_prefix), std::cend(dom_prefix));
                    dom.push_back(phflag);
                    dom.push_back(context_len);
                    std::copy(std::cbegin(params_type::context), std::cend(params_type::context),
                              std::back_inserter(dom));

                    return dom;
                }
            };

            template<typename Params>
            struct eddsa_policy<EddsaVariant::ctx, Params> {
                typedef Params params_type;
                typedef std::vector<std::uint8_t> dom_type;
                typedef hashes::sha2<512> hash_type;
                typedef padding::emsa1<typename hash_type::digest_type, hash_type> padding_policy;

                static constexpr std::uint8_t phflag = 1;

                static inline dom_type get_dom() {
                    std::size_t context_len =
                        std::distance(std::cbegin(params_type::context), std::cend(params_type::context));
                    assert(0 <= context_len && context_len <= 255);

                    std::string dom_prefix = "SigEd25519 no Ed25519 collisions";
                    dom_type dom(std::cbegin(dom_prefix), std::cend(dom_prefix));
                    dom.push_back(phflag);
                    dom.push_back(context_len);
                    std::copy(std::cbegin(params_type::context), std::cend(params_type::context),
                              std::back_inserter(dom));

                    return dom;
                }
            };

            template<typename CurveGroup, EddsaVariant eddsa_variant, typename Params>
            struct eddsa;

            template<typename Coordinates, EddsaVariant eddsa_variant, typename Params>
            struct eddsa<
                typename algebra::curves::curve25519::g1_type<Coordinates, algebra::curves::forms::twisted_edwards>,
                eddsa_variant, Params> {
                typedef
                    typename algebra::curves::curve25519::g1_type<Coordinates, algebra::curves::forms::twisted_edwards>
                        group_type;
                typedef eddsa_policy<eddsa_variant, Params> policy_type;
            };

            template<typename CurveGroup, EddsaVariant eddsa_variant, typename Params>
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
                typedef nil::crypto3::marshalling::types::curve_element<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>, group_type>
                    marshalling_group_value_type;
                typedef nil::crypto3::marshalling::types::field_element<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>, scalar_field_type>
                    marshalling_scalar_field_value_type;
                typedef nil::crypto3::marshalling::types::integral<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>, scalar_integral_type>
                    marshalling_scalar_integral_type;
                typedef nil::crypto3::marshalling::types::integral<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>, base_integral_type>
                    marshalling_base_integral_type;
                typedef nil::crypto3::marshalling::types::integral<
                    nil::marshalling::field_type<nil::marshalling::option::little_endian>,
                    nil::crypto3::multiprecision::uint512_t>
                    marshalling_uint512_t_type;

                static constexpr std::size_t public_key_octets = 32;
                typedef std::array<std::uint8_t, public_key_octets> public_key_type;
                static constexpr std::size_t signature_octets = 64;
                typedef std::array<std::uint8_t, signature_octets> signature_type;

                public_key() = delete;
                public_key(const public_key_type &key) : pubkey(key) {
                }

                inline public_key_type public_key_data() const {
                    return pubkey;
                }

            protected:
                public_key_type pubkey;
            };

            template<typename CurveGroup, EddsaVariant eddsa_variant, typename Params>
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
                typedef typename scheme_public_key_type::base_integral_type base_integral_type;

                typedef typename scheme_public_key_type::endianness endianness;
                typedef typename scheme_public_key_type::marshalling_group_value_type marshalling_group_value_type;
                typedef typename scheme_public_key_type::marshalling_scalar_field_value_type
                    marshalling_scalar_field_value_type;
                typedef typename scheme_public_key_type::marshalling_base_integral_type marshalling_base_integral_type;
                typedef typename scheme_public_key_type::marshalling_uint512_t_type marshalling_uint512_t_type;

                static constexpr std::size_t private_key_octets = 32;
                typedef std::array<std::uint8_t, private_key_octets> private_key_type;
                static constexpr std::size_t public_key_octets = scheme_public_key_type::public_key_octets;
                typedef typename scheme_public_key_type::public_key_type public_key_type;
                static constexpr std::size_t signature_octets = scheme_public_key_type::signature_octets;
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
                    nil::marshalling::status_type status =
                        marshalling_group_value.write(write_iter, public_key_octets * 8);

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
                    hash<hash_type>(policy_type::get_dom(), hash_acc_2);
                    hash<hash_type>(std::cbegin(h_privkey) + private_key_octets, std::cend(h_privkey), hash_acc_2);
                    hash<hash_type>(ph_m, hash_acc_2);
                    typename hash_type::digest_type h_2 = nil::crypto3::accumulators::extract::hash<hash_type>(hash_acc_2);
                    marshalling_uint512_t_type marshalling_uint512_t_2;
                    auto h_2_it = std::cbegin(h_2);
                    // TODO: process status
                    nil::marshalling::status_type status = marshalling_uint512_t_2.read(h_2_it, hash_type::digest_bits);
                    nil::crypto3::multiprecision::uint512_t r = marshalling_uint512_t_2.value();
                    scalar_field_value_type r_reduced(r);

                    // 3.
                    group_value_type rB = r_reduced * group_value_type::one();
                    marshalling_group_value_type marshalling_group_value(rB);
                    public_key_type R;
                    auto write_iter = std::begin(R);
                    // TODO: process status
                    status = marshalling_group_value.write(write_iter, public_key_octets * 8);

                    // 4.
                    accumulator_set<hash_type> hash_acc_4;
                    hash<hash_type>(policy_type::get_dom(), hash_acc_4);
                    hash<hash_type>(R, hash_acc_4);
                    hash<hash_type>(this->pubkey, hash_acc_4);
                    hash<hash_type>(ph_m, hash_acc_4);
                    typename hash_type::digest_type h_4 = nil::crypto3::accumulators::extract::hash<hash_type>(hash_acc_4);
                    marshalling_uint512_t_type marshalling_uint512_t_4;
                    auto h_4_it = std::cbegin(h_2);
                    // TODO: process status
                    status = marshalling_uint512_t_4.read(h_4_it, hash_type::digest_bits);
                    nil::crypto3::multiprecision::uint512_t k = marshalling_uint512_t_4.value();
                    scalar_field_value_type k_reduced(k);

                    // 5.
                    // scalar_field_value_type S = r_reduced + k_reduced *
                }

            protected:
                // https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5
                static inline base_integral_type construct_scalar(const typename hash_type::digest_type &h) {
                    // 3.
                    marshalling_base_integral_type marshalling_base_integral;
                    auto h_it = std::cbegin(h);
                    marshalling_base_integral.read(h_it, private_key_octets * 8);
                    base_integral_type s = marshalling_base_integral.value();

                    // 2.
                    s &= ((base_integral_type(1) << 254) - 8);
                    s |= (base_integral_type(1) << 254);

                    return s;
                }

                private_key_type privkey;
                typename hash_type::digest_type h_privkey;
                scalar_field_value_type s_reduced;
            };

        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_EDDSA_HPP
