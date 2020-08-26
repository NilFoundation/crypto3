//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_GT_HPP
#define ALGEBRA_CURVES_BN128_GT_HPP

#include <nil/algebra/fields/fp.hpp>

#include <boost/multiprecision/modular/base_params.hpp>
#include <boost/multiprecision/detail/functions/pow.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using params_type = arithmetic_params<fp<ModulusBits, GeneratorBits>>;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using modulus_type = params_type<ModulusBits, GeneratorBits>::modulus_type;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using fp12_type = fp12<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                using value_type = element<fp12_type<ModulusBits, GeneratorBits>>;

                struct bn128_gt {
                    value_type elem;

                    bn128_gt() {
                        elem = value_type::zero();
                    }

                    bn128_gt(value_type X) {
                        elem = X;
                    }

                    bool operator==(const bn128_gt &other) const {
                        return (elem == other.elem);
                    }
                    bool operator!=(const bn128_gt &other) const {
                        return !(operator==(other));
                    }

                    bn128_gt operator*(const bn128_gt &other) const {
                        bn128_gt result;
                        result.elem = elem * other.elem;
                        return result;
                    }

                    bn128_gt unitary_inverse() const {
                        bn128_gt result(*this);
                        bn::Fp6::neg(result.elem.b_, result.elem.b_);
                        return result;
                    }

                    static bn128_gt one() {
                        return value_type::one();
                    }
                };

                template<typename NumberType>
                bn128_gt operator^(const bn128_gt &rhs, const NumberType &lhs) {
                    return scalar_mul<bn128_gt, m>(rhs, lhs);
                }

                template<typename NumberType, const NumberType &modulus_p>
                bn128_gt operator^(const bn128_gt &rhs, const Fp_model<m, modulus_p> &lhs) {
                    return scalar_mul<bn128_gt, m>(rhs, lhs.as_bigint());
                }

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_GT_HPP
