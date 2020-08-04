//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <nil/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct bls_public_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
            };

            template<typename CurveType>
            struct bls_private_key {
                typedef CurveType curve_type;

                typedef typename curve_type::value_type value_type;
                typedef typename curve_type::number_type number_type;

                constexpr static const std::size_t key_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_type;

                constexpr static const std::size_t key_schedule_bits = curve_type::field_type::modulus_bits;
                typedef typename curve_type::value_type key_schedule_type;

                constexpr static const std::size_t signature_bits = curve_type::field_type::modulus_bits * 2;
                typedef std::tuple<value_type, value_type> signature_type;
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
