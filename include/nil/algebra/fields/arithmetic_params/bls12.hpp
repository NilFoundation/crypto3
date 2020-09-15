//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP
#define ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP

#include <nil/algebra/fields/params.hpp>

#include <nil/algebra/fields/bls12/base_field.hpp>
#include <nil/algebra/fields/bls12/scalar_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            /************************* BLS12-381 ***********************************/

            template<>
            struct arithmetic_params<bls12_base_field<381, CHAR_BIT>>
                : public params<bls12_base_field<381, CHAR_BIT>> {
            private:
                typedef params<bls12_base_field<381, CHAR_BIT>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0xD0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555_cppui380;
            };

            template<>
            struct arithmetic_params<fp2<bl12_base_field<381, CHAR_BIT>>>
                : public params<bl12_base_field<381, CHAR_BIT>> {
            private:
                typedef params<bl12_base_field<381, CHAR_BIT>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                0x1521BD25C61AFE3A5E93C75511792F4F16E48728738235A3372CF249A4F45E82853167E8B6EE5377A98A49984BC77808EB430CE430C2E3D949742D43848D024B35FC8F69F38DBA18B1619C1B1089E7EBE76B58EBB1C1755935500000E38C71C_cppui761;

            };

            template<>
            struct arithmetic_params<bls12_scalar_field<381, CHAR_BIT>>
                : public params<bls12_scalar_field<381, CHAR_BIT>> {
            private:
                typedef params<bls12_scalar_field<381, CHAR_BIT>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x39F6D3A994CEBEA4199CEC0404D0EC02A9DED2017FFF2DFF7FFFFFFF80000000_cppui254;
            };

            /************************* BLS12-377 ***********************************/
            
            template<>
            struct arithmetic_params<bls12_base_field<377, CHAR_BIT>>
                : public params<bls12_base_field<377, CHAR_BIT>> {
            private:
                typedef params<bls12_base_field<377, CHAR_BIT>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0xD71D230BE28875631D82E03650A49D8D116CF9807A89C78F79B117DD04A4000B85AEA2180000004284600000000000_cppui376;
            };

            template<>
            struct arithmetic_params<bls12_scalar_field<377, CHAR_BIT>>
                : public params<bls12_scalar_field<377, CHAR_BIT>> {
            private:
                typedef params<bls12_scalar_field<377, CHAR_BIT>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x955B2AF4D1652AB305A268F2E1BD800ACD53B7F680000008508C00000000000_cppui252;
            };

        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BLS12_ARITHMETIC_PARAMS_HPP
