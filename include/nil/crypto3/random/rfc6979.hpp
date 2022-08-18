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

#ifndef CRYPTO3_RANDOM_HMAC_DRBG_HPP
#define CRYPTO3_RANDOM_HMAC_DRBG_HPP

#include <type_traits>
#include <ostream>
#include <istream>
#include <bitset>

#include <boost/random/detail/seed.hpp>

#include <nil/crypto3/mac/hmac.hpp>
#include <nil/crypto3/mac/algorithm/compute.hpp>

#include <nil/marshalling/types/integral.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace random {
            // TODO: extend this rfc6979-specific version of HMAC_DRBG
            //  (https://datatracker.ietf.org/doc/html/rfc6979#section-3.2) according to
            //  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
            //
            // TODO: fix reseed
            template<typename ResultType, typename Hash, typename = void>
            struct rfc6979;

            template<typename ResultType, typename Hash>
            struct rfc6979<
                ResultType,
                Hash,
                typename std::enable_if<algebra::is_field<typename ResultType::field_type>::value &&
                                        !algebra::is_extended_field<typename ResultType::field_type>::value>::type> {
                typedef Hash hash_type;
                typedef mac::hmac<hash_type> hmac_policy;
                typedef mac::mac_key<hmac_policy> key_type;
                typedef ResultType result_type;
                typedef result_type field_value_type;
                typedef typename result_type::field_type field_type;
                typedef typename field_type::modular_type modular_type;
                typedef typename field_type::integral_type integral_type;
                typedef typename hash_type::digest_type digest_type;
                typedef mac::computation_accumulator_set<mac::computation_policy<hmac_policy>>
                    internal_accumulator_type;

                typedef ::nil::crypto3::marshalling::types::
                    integral<::nil::marshalling::field_type<::nil::marshalling::option::big_endian>, integral_type>
                        marshalling_integral_value_be_type;
                typedef ::nil::crypto3::marshalling::types::
                    integral<::nil::marshalling::field_type<::nil::marshalling::option::little_endian>, integral_type>
                        marshalling_integral_value_le_type;

                constexpr static std::size_t modulus_bits = field_type::modulus_bits;
                constexpr static std::size_t modulus_octets =
                    modulus_bits / 8 + static_cast<std::size_t>(modulus_bits % 8 != 0);
                constexpr static std::size_t digest_bits = hmac_policy::digest_bits;
                constexpr static std::size_t digest_octets =
                    digest_bits / 8 + static_cast<std::size_t>(digest_bits % 8 != 0);
                constexpr static std::size_t digest_chunks =
                    modulus_bits / digest_bits + static_cast<std::size_t>(modulus_bits % digest_bits != 0);

                typedef std::array<std::uint8_t, modulus_octets> modulus_octets_container_type;

                static_assert(
                    std::is_same<std::uint8_t,
                                 typename std::iterator_traits<typename digest_type::iterator>::value_type>::value,
                    "Hash output value type is not uint8_t");

                explicit rfc6979(const result_type& x, const digest_type& h1) {
                    seed(x, h1);
                }

                // TODO: move to marshalling
                // TODO: creating of new vector is a bottleneck
                template<typename InputRange,
                         typename ValueType = typename std::iterator_traits<typename InputRange::iterator>::value_type,
                         typename std::enable_if<std::is_unsigned<ValueType>::value, bool>::type = true>
                static inline std::vector<ValueType> adjust_bitstring(InputRange& range) {
                    // TODO: local_char_bits is supposed to equal chunk_size from import_bits call in marshalling
                    constexpr std::size_t local_char_bits = 8;
                    constexpr std::size_t adjustment_shift = modulus_octets * local_char_bits - modulus_bits;
                    constexpr std::size_t chunk_size = std::numeric_limits<ValueType>::digits;
                    using bitset_repr_type = std::bitset<chunk_size>;

                    auto carry_bits = [&](bitset_repr_type& current_bits,
                                          const bitset_repr_type& carried_bits) -> bitset_repr_type {
                        bitset_repr_type new_carried_bits;

                        for (auto i = 0; i < adjustment_shift; ++i) {
                            new_carried_bits.set(adjustment_shift - 1 - i, current_bits[adjustment_shift - 1 - i]);
                        }
                        current_bits >>= adjustment_shift;
                        for (auto i = 0; i < adjustment_shift; ++i) {
                            current_bits.set(local_char_bits - 1 - i, carried_bits[adjustment_shift - 1 - i]);
                        }

                        return new_carried_bits;
                    };

                    std::vector<ValueType> result;
                    bitset_repr_type carried_bits;

                    for (const auto v : range) {
                        bitset_repr_type v_bitset_repr(v);
                        carried_bits = carry_bits(v_bitset_repr, carried_bits);
                        result.template emplace_back(static_cast<ValueType>(v_bitset_repr.to_ullong()));
                    }
                    bitset_repr_type v_bitset_repr;
                    carry_bits(v_bitset_repr, carried_bits);
                    result.template emplace_back(static_cast<ValueType>(v_bitset_repr.to_ullong()));

                    return result;
                }

                template<typename InputRange,
                         typename ValueType = typename std::iterator_traits<typename InputRange::iterator>::value_type,
                         typename std::enable_if<std::is_same<std::uint8_t, ValueType>::value, bool>::type = true>
                static inline integral_type bits2int(const InputRange& range) {
                    integral_type result;
                    if (modulus_bits < range.size() * 8) {
                        auto adjusted_range = adjust_bitstring(range);
                        marshalling_integral_value_be_type marshalling_integral_value_be;
                        auto it = adjusted_range.cbegin();
                        marshalling_integral_value_be.template read(it, modulus_octets);
                        result = marshalling_integral_value_be.value();
                    } else {
                        // TODO: creating copy of input range of modulus_octets size is a bottleneck:
                        //  extend marshalling interface by function supporting initialization from container which
                        //  length is less than modulus_octets
                        // TODO: check need for adjust_bitstring call
                        modulus_octets_container_type range_padded;
                        range_padded.fill(0);
                        std::copy(std::crbegin(range), std::crend(range), std::rbegin(range_padded));
                        marshalling_integral_value_be_type marshalling_integral_value_be;
                        auto it = std::cbegin(range_padded);
                        marshalling_integral_value_be.template read(it, range_padded.size());
                        result = marshalling_integral_value_be.value();
                    }
                    return result;
                }

                template<typename InputRange>
                static inline modulus_octets_container_type bits2octets(const InputRange& range) {
                    nil::marshalling::status_type status;
                    return ::nil::marshalling::pack<::nil::marshalling::option::big_endian>(
                        field_value_type(bits2int(range)), status);
                }

                inline void seed(const result_type& x, const digest_type& h1) {
                    // b.
                    std::fill(V.begin(), V.end(), 1);

                    // c.
                    std::fill(K.begin(), K.end(), 0);
                    key_type Key(K);

                    // d.
                    internal_accumulator_type acc_d(Key);
                    
                    nil::marshalling::status_type status;
                    modulus_octets_container_type int2octets_x =
                        ::nil::marshalling::pack<::nil::marshalling::option::big_endian>(x, status);

                    auto bits2octets_h1 = bits2octets(h1);
                    compute<hmac_policy>(V, acc_d);
                    compute<hmac_policy>(std::array<std::uint8_t, 1> {0}, acc_d);
                    compute<hmac_policy>(int2octets_x, acc_d);
                    compute<hmac_policy>(bits2octets_h1, acc_d);
                    Key = key_type(
                        ::nil::crypto3::accumulators::extract::mac<mac::computation_policy<hmac_policy>>(acc_d));

                    // e.
                    V = compute<hmac_policy>(V, Key);

                    // f.
                    internal_accumulator_type acc_f(Key);
                    compute<hmac_policy>(V, acc_f);
                    compute<hmac_policy>(std::array<std::uint8_t, 1> {1}, acc_f);
                    compute<hmac_policy>(int2octets_x, acc_f);
                    compute<hmac_policy>(bits2octets_h1, acc_f);
                    K = ::nil::crypto3::accumulators::extract::mac<mac::computation_policy<hmac_policy>>(acc_f);
                    Key = key_type(K);

                    // g.
                    V = compute<hmac_policy>(V, Key);
                }

                inline result_type operator()() {
                    // h.
                    do {
                        std::array<std::uint8_t, digest_chunks * digest_octets> T;

                        // h.2.
                        key_type Key(K);
                        for (auto i = 0; i < digest_chunks; i++) {
                            V = compute<hmac_policy>(V, Key);
                            std::copy(V.cbegin(), V.cend(), T.begin() + i * digest_octets);
                        }

                        // h.3.
                        integral_type k = bits2int(T);
                        if (0 < k && k < field_type::modulus) {
                            return k;
                        }

                        internal_accumulator_type acc_h3(Key);
                        compute<hmac_policy>(V, acc_h3);
                        compute<hmac_policy>(std::array<std::uint8_t, 1> {0}, acc_h3);
                        K = ::nil::crypto3::accumulators::extract::mac<mac::computation_policy<hmac_policy>>(acc_h3);

                        Key = key_type(K);
                        V = compute<hmac_policy>(V, Key);
                    } while (true);
                }

            protected:
                digest_type V;
                digest_type K;
            };
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RANDOM_HMAC_DRBG_HPP
