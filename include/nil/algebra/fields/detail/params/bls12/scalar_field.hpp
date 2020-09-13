//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BLS12_FR_PARAMS_HPP
#define ALGEBRA_FIELDS_BLS12_FR_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/bls12/scalar_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<>
                struct extension_params<bls12_scalar_field<381, CHAR_BIT>>
                    : public params<bls12_scalar_field<381, CHAR_BIT>> {
                private:
                    typedef params<bls12_scalar_field<381, CHAR_BIT>> policy_type;
                    typedef extension_params<bls12_scalar_field<381, CHAR_BIT>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF7FFFFFFF80000000_cppui254;
                };

                template<>
                struct extension_params<bls12_scalar_field<377, CHAR_BIT>>
                    : public params<bls12_scalar_field<377, CHAR_BIT>> {
                private:
                    typedef params<bls12_scalar_field<377, CHAR_BIT>> policy_type;
                    typedef extension_params<bls12_scalar_field<377, CHAR_BIT>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x955B2AF4D1652AB305A268F2E1BD800ACD53B7F680000008508C00000000000_cppui252;
                };

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BLS12_FR_PARAMS_HPP
