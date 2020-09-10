//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <nil/algebra/algorithms/pair.hpp>
#include <nil/algebra/curves/bls12.hpp>
#include <nil/algebra/pairing/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType, typename SignatureHash = hashes::sha2<256>>
            struct bls_public_key {
                typedef CurveType curve_type;
                typedef SignatureHash signature_hash_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::g2_type::modulus_bits;
                typedef typename curve_type::g2_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = key_bits;
                typedef key_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::g1_type::modulus_bits;
                typedef typename curve_type::g1_type::value_type signature_type;

                template<typename InputRange>
                inline static bool verify(const InputRange &val, const signature_type &sign, const key_type &key) {
                    if (!sign.is_well_formed()) {
                        return false;
                    }

                    if (!key.is_well_formed()) {
                        return false;
                    }

                    if (CurveType::modulus_r * sign != typename CurveType::g1_type::value_type::zero()) {
                        return false;
                    }

                    signature_type hash = Hashing(val);

                    return (algebra::reduced_pair<CurveType>(sign, key_type::value_type::one()) ==
                            algebra::reduced_pair<CurveType>(hash, key));
                }
            };

            template<typename CurveType>
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

                inline static bool sign(signature_type &res, const signature_type &val, const key_type &key) {
                    res = val * key;
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
