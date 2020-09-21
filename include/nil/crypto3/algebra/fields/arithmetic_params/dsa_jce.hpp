//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/dsa_jce/base_field.hpp>
#include <nil/crypto3/algebra/fields/dsa_jce/scalar_field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct arithmetic_params<dsa_jce_base_field<ModulusBits, GeneratorBits>>
                    : public params<dsa_jce_base_field<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<dsa_jce_base_field<ModulusBits, GeneratorBits>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x9760508F15230BCCB292B982A2EB840BF0581CF5_cppui160;
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename arithmetic_params<dsa_jce_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    arithmetic_params<dsa_jce_base_field<ModulusBits, GeneratorBits>>::group_order;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP
