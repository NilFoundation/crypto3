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

#ifndef CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP
#define CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/h2c/ep.hpp>
#include <nil/crypto3/algebra/curves/detail/h2c/ep2.hpp>

#include <cstddef>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                using namespace algebra::curves::detail;

                template<typename CurveType, typename HashType,
                         /// HashType::digest_type is required to be uint8_t[]
                         typename = typename std::enable_if<
                             std::is_same<std::uint8_t, typename HashType::digest_type::value_type>::value>::type>
                struct bls_basic_policy {
                    typedef CurveType curve_type;
                    typedef HashType hash_type;

                    typedef typename curve_type::pairing_policy pairing_type;
                    typedef typename curve_type::scalar_field_type field_type;
                    typedef typename field_type::value_type private_key_type;
                    typedef typename private_key_type::modulus_type modulus_type;
                    typedef typename pairing_type::gt_type::value_type gt_value_type;

                    constexpr static std::size_t private_key_bits = field_type::modulus_bits;
                    constexpr static modulus_type r = curve_type::q;
                };

                //
                // Minimal-signature-size
                // Random oracle version of hash-to-point
                //
                template<typename CurveType, typename HashType>
                struct bls_policy_mss_ro {
                    typedef bls_basic_policy<CurveType, HashType> basic_policy;

                    typedef typename basic_policy::curve_type curve_type;
                    typedef typename basic_policy::hash_type hash_type;
                    typedef typename basic_policy::gt_value_type gt_value_type;
                    typedef typename basic_policy::pairing_type pairing_type;
                    typedef typename basic_policy::modulus_type modulus_type;

                    typedef typename curve_type::g2_type public_key_group_type;
                    typedef typename curve_type::g1_type signature_group_type;

                    typedef typename basic_policy::private_key_type private_key_type;
                    typedef typename public_key_group_type::value_type public_key_type;
                    typedef typename signature_group_type::value_type signature_type;

                    constexpr static const std::size_t private_key_bits = basic_policy::private_key_bits;
                    constexpr static const std::size_t public_key_bits = public_key_type::value_bits;
                    constexpr static const std::size_t signature_bits = signature_type::value_bits;

                    // typedef ep_map<signature_group_type> hash_to_point;
                    // typedef ep2_map<public_key_group_type> hash_pubkey_to_point;

                    template<typename MsgType, typename DstType>
                    static inline signature_type hash_to_point(const MsgType &msg, const DstType &dst) {
                        using hash_to_point_type = ep_map<signature_group_type>;

                        return hash_to_point_type::hash_to_curve(msg, dst);
                    }

                    static inline gt_value_type pairing(const signature_type &U, const public_key_type &V) {
                        // TODO: or reduced_pairing
                        return pairing_type::reduced_pairing(U, V);
                    }
                };

                //
                // Minimal-pubkey-size
                // Random oracle version of hash-to-point
                //
                template<typename CurveType, typename HashType>
                struct bls_policy_mps_ro {
                    typedef bls_basic_policy<CurveType, HashType> basic_policy;

                    typedef typename basic_policy::curve_type curve_type;
                    typedef typename basic_policy::hash_type hash_type;
                    typedef typename basic_policy::gt_value_type gt_value_type;
                    typedef typename basic_policy::pairing_type pairing_type;
                    typedef typename basic_policy::modulus_type modulus_type;

                    typedef typename curve_type::g1_type public_key_group_type;
                    typedef typename curve_type::g2_type signature_group_type;

                    typedef typename basic_policy::private_key_type private_key_type;
                    typedef typename public_key_group_type::value_type public_key_type;
                    typedef typename signature_group_type::value_type signature_type;

                    constexpr static const std::size_t private_key_bits = basic_policy::private_key_bits;
                    constexpr static const std::size_t public_key_bits = public_key_type::value_bits;
                    constexpr static const std::size_t signature_bits = signature_type::value_bits;

                    // typedef ep2_map<signature_group_type> hash_to_point;
                    // typedef ep_map<public_key_group_type> hash_pubkey_to_point;

                    template<typename MsgType, typename DstType>
                    static inline signature_type hash_to_point(const MsgType &msg, const DstType &dst) {
                        using hash_to_point_type = ep2_map<signature_group_type>;

                        return hash_to_point_type::hash_to_curve(msg, dst);
                    }

                    static inline gt_value_type pairing(const signature_type &U, const public_key_type &V) {
                        // TODO: or reduced_pairing
                        return pairing_type::reduced_pairing(V, U);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP
