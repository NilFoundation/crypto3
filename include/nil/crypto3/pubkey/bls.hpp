//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <cstdint>
#include <array>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType, typename SignatureHash = hashes::sha2<256>>
            struct bls_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::scalar_field_type::modulus_bits;
                typedef typename curve_type::scalar_field_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = key_bits;
                typedef key_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::g1_type::modulus_bits;
                typedef typename curve_type::g1_type::value_type signature_type;

                inline static bool is_well_formed(const key_type &privkey) {
                    // privkey < r is implicitly true due to scalar_field_type implementation
                    return privkey != 0;
                }

                template<std::size_t N, typename = std::enable_if_t<N >= 32>>
                inline static key_type key_gen(const std::array<uint8_t, N> &seed) {
                    return key_gen_impl(seed);
                }

                inline static key_type key_gen(const std::vector<uint8_t> &seed) {
                    assert(seed.size() < 32);
                    return key_gen_impl(seed);
                }

                inline static bool sign(signature_type &res, const signature_type &val, const key_type &key) {
                    // res = val * key;
                }

            private:
                // TODO: temporary stub -- remove
                inline static number_type hkdf_extract_expand() {
                    return 1234;
                }

                template<typename SeedType>
                inline static key_type key_gen_impl(const SeedType &seed) {
                    // "BLS-SIG-KEYGEN-SALT-"
                    std::array<uint8_t, 20> salt = {66, 76, 83, 45, 83, 73, 71, 45, 75, 69,
                                        89, 71, 69, 78, 45, 83, 65, 76, 84, 45};
                    number_type sk(0);
                    // TODO: will work when hkdf finished
                    while (sk != 0) {
                        salt = hash<hashes::sha2<512>>(salt);
                        sk = hkdf_extract_expand(salt, seed);
                    }
                    return key_type(sk);
                }
            };

            template<typename CurveType, typename SignatureHash = hashes::sha2<256>>
            struct bls_public_key {
                typedef CurveType curve_type;
                typedef SignatureHash signature_hash_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::g2_type::modulus_bits;
                constexpr static const number_type group_order = curve_type::q;
                typedef typename curve_type::g2_type::value_type key_type;
                typedef typename bls_private_key<CurveType>::key_type private_key_type;

                constexpr static const std::size_t key_schedule_bits = key_bits;
                typedef key_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::g1_type::modulus_bits;
                typedef typename curve_type::g1_type::value_type signature_type;

                inline static bool is_well_formed(const key_type &pubkey) {
                    bool status = true;
                    status &= (pubkey != key_type::one());
                    // TODO: will work after scalar multiplication finished
                    status &= (pubkey * group_order == key_type::one());
                    return status;
                }

                inline static key_type key_gen(const private_key_type &privkey) {
                    // TODO: will work after scalar multiplication finished
                    key_type pubkey = privkey * group_order;
                    // This action is not necessary while key generation
                    assert(is_well_formed(pubkey));
                    return pubkey;
                }

                template<typename InputRange>
                inline static bool verify(const InputRange &val, const signature_type &sign, const key_type &key) {
                    // if (!sign.is_well_formed()) {
                    //     return false;
                    // }
                    //
                    // if (!key.is_well_formed()) {
                    //     return false;
                    // }
                    //
                    // if (CurveType::modulus_r * sign != typename CurveType::g1_type::value_type::zero()) {
                    //     return false;
                    // }
                    //
                    // signature_type hash = Hashing(val);
                    //
                    // return (algebra::reduced_pair<CurveType>(sign, key_type::value_type::one()) ==
                    //         algebra::reduced_pair<CurveType>(hash, key));
                }

            private:

            };

            template<typename CurveType>
            struct bls {
                typedef CurveType curve_type;

                typedef bls_public_key<curve_type> public_key_type;
                typedef bls_private_key<curve_type> private_key_type;

                constexpr static const std::size_t public_key_bits = public_key_type::key_bits;
                constexpr static const std::size_t private_key_bits = private_key_type::key_bits;

                explicit bls() {}
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
