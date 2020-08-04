//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN128_GT_HPP
#define ALGEBRA_FF_BN128_GT_HPP

#include <nil/algebra/fields/fp.hpp>

#include <boost/multiprecision/modular/base_params.hpp>
#include <boost/multiprecision/detail/functions/pow.hpp>

namespace nil {
    namespace algebra {

        template <typename ModulusBits, typename GeneratorBits>
        using params_type = arithmetic_params<fp<ModulusBits, GeneratorBits>>;

        template <typename ModulusBits, typename GeneratorBits>
        using modulus_type = params_type<ModulusBits, GeneratorBits>::modulus_type;

        template <typename ModulusBits, typename GeneratorBits>
        using fp2_type = fp2<ModulusBits, GeneratorBits>;

        template <typename ModulusBits, typename GeneratorBits>
        using value_type = element<fp2_type<ModulusBits, GeneratorBits>>;

        struct bn128_GT {
            static bn128_GT GT_one;
            value_type elem;

            bn128_GT() {
                elem.clear();
            }
            bool operator==(const bn128_GT &other) const {
                return (elem == other.elem);
            }
            bool operator!=(const bn128_GT &other) const {
                return !(operator==(other));
            }

            bn128_GT operator*(const bn128_GT &other) const {
                bn128_GT result;
                result.elem = elem * other.elem;
                return result;
            }

            bn128_GT unitary_inverse() const {
                bn128_GT result(*this);
                bn::Fp6::neg(result.elem.b_, result.elem.b_);
                return result;
            }

            static bn128_GT one() {
                return GT_one;
            }

        };

        template<typename NumberType>
        bn128_GT operator^(const bn128_GT &rhs, const NumberType &lhs) {
            return scalar_mul<bn128_GT, m>(rhs, lhs);
        }

        template<typename NumberType, const NumberType &modulus_p>
        bn128_GT operator^(const bn128_GT &rhs, const Fp_model<m, modulus_p> &lhs) {
            return scalar_mul<bn128_GT, m>(rhs, lhs.as_bigint());
        }

    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_FF_BN128_GT_HPP
