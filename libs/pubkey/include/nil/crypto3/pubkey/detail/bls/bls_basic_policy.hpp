//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <cstddef>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/h2c.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/detail/marshalling.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename CurveType>
                struct bls_basic_policy {
                    typedef CurveType curve_type;

                    typedef typename curve_type::scalar_field_type scalar_field_type;
                    typedef typename scalar_field_type::value_type private_key_type;
                    typedef typename scalar_field_type::modular_type scalar_modular_type;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    constexpr static std::size_t private_key_bits = scalar_field_type::modulus_bits;
                    constexpr static scalar_modular_type r = curve_type::q;
                };

                //
                // Minimal-signature-size
                // Random oracle version of hash-to-point
                //
                template<typename PublicParams, typename CurveType>
                struct bls_mss_ro_policy {
                    typedef bls_basic_policy<CurveType> basic_policy;

                    typedef typename basic_policy::curve_type curve_type;
                    typedef typename basic_policy::gt_value_type gt_value_type;
                    typedef typename basic_policy::scalar_modular_type scalar_modular_type;

                    // TODO: pass template parameters for Coordinates and Form of the group
                    typedef typename curve_type::template g2_type<> public_key_group_type;
                    typedef typename curve_type::template g1_type<> signature_group_type;

                    typedef typename basic_policy::private_key_type private_key_type;
                    typedef typename public_key_group_type::value_type public_key_type;
                    typedef typename signature_group_type::value_type signature_type;

                    typedef nil::marshalling::curve_element_serializer<curve_type> bls_serializer;
                    typedef typename bls_serializer::compressed_g2_octets public_key_serialized_type;
                    typedef typename bls_serializer::compressed_g1_octets signature_serialized_type;

                    constexpr static const std::size_t private_key_bits = basic_policy::private_key_bits;
                    constexpr static const std::size_t public_key_bits = public_key_type::value_bits;
                    constexpr static const std::size_t signature_bits = signature_type::value_bits;

                    typedef hashes::h2c<signature_group_type, hashes::sha2<256>, PublicParams> h2c_policy;
                    typedef accumulator_set<h2c_policy> internal_accumulator_type;

                    static inline gt_value_type pairing(const signature_type &U, const public_key_type &V) {
                        return algebra::pair_reduced<curve_type>(U, V);
                    }
                };

                //
                // Minimal-pubkey-size
                // Random oracle version of hash-to-point
                //
                template<typename PublicParams, typename CurveType>
                struct bls_mps_ro_policy {
                    typedef bls_basic_policy<CurveType> basic_policy;

                    typedef typename basic_policy::curve_type curve_type;
                    typedef typename basic_policy::gt_value_type gt_value_type;
                    typedef typename basic_policy::scalar_modular_type scalar_modular_type;

                    // TODO: pass template parameters for Coordinates and Form of the group
                    typedef typename curve_type::template g1_type<> public_key_group_type;
                    typedef typename curve_type::template g2_type<> signature_group_type;

                    typedef typename basic_policy::private_key_type private_key_type;
                    typedef typename public_key_group_type::value_type public_key_type;
                    typedef typename signature_group_type::value_type signature_type;

                    typedef nil::marshalling::curve_element_serializer<curve_type> bls_serializer;
                    typedef typename bls_serializer::compressed_g1_octets public_key_serialized_type;
                    typedef typename bls_serializer::compressed_g2_octets signature_serialized_type;

                    constexpr static const std::size_t private_key_bits = basic_policy::private_key_bits;
                    constexpr static const std::size_t public_key_bits = public_key_type::value_bits;
                    constexpr static const std::size_t signature_bits = signature_type::value_bits;

                    typedef hashes::h2c<signature_group_type, hashes::sha2<256>, PublicParams> h2c_policy;
                    typedef accumulator_set<h2c_policy> internal_accumulator_type;

                    static inline gt_value_type pairing(const signature_type &U, const public_key_type &V) {
                        return algebra::pair_reduced<curve_type>(V, U);
                    }

                    static inline public_key_serialized_type point_to_pubkey(const public_key_type &pubkey) {
                        return bls_serializer::point_to_octets_compress(pubkey);
                    }

                    static inline signature_serialized_type point_to_signature(const signature_type &sig) {
                        return bls_serializer::point_to_octets_compress(sig);
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_BASIC_POLICY_HPP
