//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_HPP
#define ALGEBRA_CURVES_BLS12_HPP

#include <nil/algebra/curves/detail/bls12/g1.hpp>
#include <nil/algebra/curves/detail/bls12/g2.hpp>

#include <nil/algebra/fields/bls12/fq.hpp>
#include <nil/algebra/fields/bls12/fr.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            /*
                E/Fp: y^2 = x^3 + 4.
            */

            template<std::size_t ModulusBits>
            struct bls12 { };

            template<>
            struct bls12<381> {

                constexpr static const std::size_t base_field_bits = 381;
                typedef fields::bls12_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 255;
                typedef fields::bls12_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::bls12_g1<254> g1_type;
                typedef typename detail::bls12_g2<254> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp12_2over3over2<
                    nil::algebra::fields::detail::arithmetic_params<bls_fq<381, CHAR_BIT>>>
                    gt_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a = 0;
                constexpr static const number_type b = 0x04;
                constexpr static const number_type x =
                    0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb_cppui381;
                constexpr static const number_type y =
                    0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1_cppui381;
            };

            typedef bls12<381> bls12_381;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_BLS12_381_HPP
