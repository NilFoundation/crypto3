//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/pubkey/detail/bls/bls_basic_key_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_functions.hpp>

#include <cstdint>
#include <array>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType, typename SignatureHash = hashes::sha2<256>>
            struct bls_private_key {
                typedef detail::bls_basic_key_policy<CurveType, SignatureHash> basic_key_policy_type;
                typedef detail::bls_functions<CurveType, SignatureHash> bls_functions;

                typedef typename basic_key_policy_type::private_key_type private_key_type;
                typedef typename basic_key_policy_type::signature_type signature_type;

                inline static bool is_well_formed(const private_key_type &private_key) {
                    // private_key < r is implicitly true due to scalar_field_type implementation
                    return private_key != 0;
                }

                template<std::size_t N, typename = std::enable_if_t<N >= 32>>
                inline static private_key_type key_gen(const std::array<uint8_t, N> &seed) {
                    return key_gen_impl(seed);
                }

                inline static private_key_type key_gen(const std::vector<uint8_t> &seed) {
                    assert(seed.size() < 32);
                    return bls_functions::key_gen_impl(seed);
                }

                template<typename InputRange>
                inline static bool sign(signature_type &result, const InputRange &message,
                                        const private_key_type &private_key) {
                    result = message * private_key;
                }
            };

            template<typename CurveType, typename SignatureHash = hashes::sha2<256>>
            struct bls_public_key {
                typedef detail::bls_basic_key_policy<CurveType, SignatureHash> basic_key_policy_type;
                typedef detail::bls_functions<CurveType, SignatureHash> bls_functions;

                typedef typename basic_key_policy_type::number_type number_type;
                typedef typename basic_key_policy_type::public_key_type public_key_type;
                typedef typename basic_key_policy_type::private_key_type private_key_type;
                typedef typename basic_key_policy_type::signature_type signature_type;

                constexpr static const number_type pubkey_subgroup_ord = basic_key_policy_type::pubkey_subgroup_ord;

                inline static bool is_well_formed(const public_key_type &public_key) {
                    bool status = true;
                    status &= (public_key != public_key_type::one());
                    // TODO: will work after scalar multiplication finished
                    status &= (public_key * pubkey_subgroup_ord == public_key_type::one());
                    return status;
                }

                inline static public_key_type key_gen(const private_key_type &private_key) {
                    // TODO: will work after scalar multiplication finished
                    public_key_type public_key = public_key_type::one() * private_key;
                    // This action is not necessary while key generation
                    assert(is_well_formed(public_key));
                    return public_key;
                }

                template<typename InputRange>
                inline static bool verify(const InputRange &message, const signature_type &sign,
                                          const public_key_type &public_key) {
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
            };

            template<typename CurveType>
            struct bls {
                typedef CurveType curve_type;

                typedef bls_public_key<curve_type> public_key_type;
                typedef bls_private_key<curve_type> private_key_type;

                constexpr static const std::size_t public_key_bits = public_key_type::key_bits;
                constexpr static const std::size_t private_key_bits = private_key_type::key_bits;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
