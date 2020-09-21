//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/dsa_jce/base_field.hpp>
#include <nil/crypto3/algebra/fields/dsa_jce/scalar_field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<>
                struct arithmetic_params<dsa_botan_base_field<2048, 2048>>
                    : public params<dsa_botan_base_field<2048, 2048>> {
                private:
                    typedef params<dsa_botan_base_field<2048, 2048>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x8CD7D450F86F0AD94EEE4CE469A8756D1EBD1058241943EAFFB0B354585E924D_cppui256;
                };

                template<>
                struct arithmetic_params<dsa_botan_base_field<3072, 3072>>
                    : public params<dsa_botan_base_field<3072, 3072>> {
                private:
                    typedef params<dsa_botan_base_field<3072, 3072>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xB3EBD364EC69EF8CF3BAF643B75734B16339B2E49E5CDE1B59C1E9FB40EE0C5B_cppui256;
                };

                constexpr typename arithmetic_params<dsa_botan_base_field<2048, 2048>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<2048, 2048>>::group_order;

                constexpr typename arithmetic_params<dsa_botan_base_field<3072, 3072>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<3072, 3072>>::group_order;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP
