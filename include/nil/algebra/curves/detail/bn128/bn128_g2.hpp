//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN128_G2_HPP
#define ALGEBRA_FF_BN128_G2_HPP

#include <vector>

#include <nil/algebra/curves/detail/bn128/bn128_init.hpp>
#include <nil/algebra/curves/detail/bn128/bn_utils.hpp>

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace algebra {

        template <typename ModulusBits, typename GeneratorBits>
        using params_type = arithmetic_params<fp2<ModulusBits, GeneratorBits>>;

        template <typename ModulusBits, typename GeneratorBits>
        using modulus_type = params_type<ModulusBits, GeneratorBits>::modulus_type;

        template <typename ModulusBits, typename GeneratorBits>
        using value_type = element<params_type<ModulusBits, GeneratorBits>, modulus_type<ModulusBits, GeneratorBits>>;

        template <typename ModulusBits, typename GeneratorBits>
        using fp2_type = fp2<ModulusBits, GeneratorBits>;

        struct bn128_G2 {

            bn128_G2() {
                coord[0] = G2_zero.coord[0];
                coord[1] = G2_zero.coord[1];
                coord[2] = G2_zero.coord[2];
            }

            void to_affine_coordinates() {
                if (is_zero()) {
                    coord[0] = 0;
                    coord[1] = 1;
                    coord[2] = 0;
                } else {
                    bn::Fp2 r;
                    r = coord[2];
                    r.inverse();
                    square(coord[2], r);
                    coord[0] *= coord[2];
                    r *= coord[2];
                    coord[1] *= r;
                    coord[2] = 1;
                }
            }

            void to_special() {
                to_affine_coordinates();
            }

            bool is_special() const {
                return (is_zero() || coord[2] == 1);
            }

            bool is_zero() const {
                return coord[2].is_zero();
            }

            bool operator==(const bn128_G2 &other) const {
                if (is_zero()) {
                    return other.is_zero();
                }

                if (other.is_zero()) {
                    return false;
                }

                /* now neither is O */

                value_type Z1sq, Z2sq, lhs, rhs;
                square(Z1sq, coord[2]);
                square(Z2sq, other.coord[2]);
                mul(lhs, Z2sq, coord[0]);
                mul(rhs, Z1sq, other.coord[0]);

                if (lhs != rhs) {
                    return false;
                }

                value_type Z1cubed, Z2cubed;
                mul(Z1cubed, Z1sq, coord[2]);
                mul(Z2cubed, Z2sq, other.coord[2]);
                mul(lhs, Z2cubed, coord[1]);
                mul(rhs, Z1cubed, other.coord[1]);

                return (lhs == rhs);
            }

            bool operator!=(const bn128_G2 &other) const {
                return !(operator==(other));
            }

            bn128_G2 operator+(const bn128_G2 &other) const {
                // handle special cases having to do with O
                if (is_zero()) {
                    return other;
                }

                if (other.is_zero()) {
                    return *this;
                }

                // no need to handle points of order 2,4
                // (they cannot exist in a prime-order subgroup)

                // handle double case, and then all the rest
                if (operator==(other)) {
                    return dbl();
                } else {
                    return add(other);
                }
            }

            bn128_G2 operator-() const {
                bn128_G2 result(*this);
                neg(result.coord[1], result.coord[1]);
                return result;
            }

            bn128_G2 operator-(const bn128_G2 &other) const {
                return (*this) + (-other);
            }

            bn128_G2 add(const bn128_G2 &other) const {

                bn128_G2 result;
                bn::ecop::ECAdd(result.coord, coord, other.coord);
                return result;
            }

            bn128_G2 mixed_add(const bn128_G2 &other) const {
                if (is_zero()) {
                    return other;
                }

                if (other.is_zero()) {
                    return *this;
                }

                // no need to handle points of order 2,4
                // (they cannot exist in a prime-order subgroup)

                // check for doubling case

                // using Jacobian coordinates so:
                // (X1:Y1:Z1) = (X2:Y2:Z2)
                // iff
                // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                // iff
                // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                // we know that Z2 = 1

                bn::Fp2 Z1Z1;
                square(Z1Z1, coord[2]);
                const bn::Fp2 &U1 = coord[0];
                bn::Fp2 U2;
                mul(U2, other.coord[0], Z1Z1);
                bn::Fp2 Z1_cubed;
                mul(Z1_cubed, coord[2], Z1Z1);

                const bn::Fp2 &S1 = coord[1];
                bn::Fp2 S2;
                mul(S2, other.coord[1], Z1_cubed);    // S2 = Y2*Z1*Z1Z1

                if (U1 == U2 && S1 == S2) {
                    // dbl case; nothing of above can be reused
                    return dbl();
                }

                bn128_G2 result;
                bn::Fp2 H, HH, I, J, r, V, tmp;
                // H = U2-X1
                sub(H, U2, coord[0]);
                // HH = H^2
                square(HH, H);
                // I = 4*HH
                add(tmp, HH, HH);
                add(I, tmp, tmp);
                // J = H*I
                mul(J, H, I);
                // r = 2*(S2-Y1)
                sub(tmp, S2, coord[1]);
                add(r, tmp, tmp);
                // V = X1*I
                mul(V, coord[0], I);
                // X3 = r^2-J-2*V
                square(result.coord[0], r);
                sub(result.coord[0], result.coord[0], J);
                sub(result.coord[0], result.coord[0], V);
                sub(result.coord[0], result.coord[0], V);
                // Y3 = r*(V-X3)-2*Y1*J
                sub(tmp, V, result.coord[0]);
                mul(result.coord[1], r, tmp);
                mul(tmp, coord[1], J);
                sub(result.coord[1], result.coord[1], tmp);
                sub(result.coord[1], result.coord[1], tmp);
                // Z3 = (Z1+H)^2-Z1Z1-HH
                add(tmp, coord[2], H);
                square(result.coord[2], tmp);
                sub(result.coord[2], result.coord[2], Z1Z1);
                sub(result.coord[2], result.coord[2], HH);
                return result;
            }

            bn128_G2 dbl() const {

                bn128_G2 result;
                bn::ecop::ECDouble(result.coord, coord);
                return result;
            }

            bool is_well_formed() const {
                if (is_zero()) {
                    return true;
                } else {
                    /*
                      y^2 = x^3 + b

                      We are using Jacobian coordinates, so equation we need to check is actually

                      (y/z^3)^2 = (x/z^2)^3 + b
                      y^2 / z^6 = x^3 / z^6 + b
                      y^2 = x^3 + b z^6
                    */
                    bn::Fp2 X2, Y2, Z2;
                    square(X2, coord[0]);
                    square(Y2, coord[1]);
                    square(Z2, coord[2]);

                    bn::Fp2 X3, Z3, Z6;
                    mul(X3, X2, coord[0]);
                    mul(Z3, Z2, coord[2]);
                    square(Z6, Z3);

                    return (Y2 == X3 + bn128_twist_coeff_b * Z6);
                }
            }

            static bn128_G2 zero() {
                return G2_zero;
            }

            static bn128_G2 one() {
                return G2_one;
            }

            static size_t size_in_bits() {
                return 2 * base_field::size_in_bits() + 1;
            }

            template<typename NumberType>
            static NumberType base_field_char() {
                return base_field::field_char();
            }

            template<typename NumberType>
            static NumberType order() {
                return scalar_field::field_char();
            }

            static void batch_to_special_all_non_zeros(std::vector<bn128_G2> &vec) {
                std::vector<bn::Fp2> Z_vec;
                Z_vec.reserve(vec.size());

                for (auto &el : vec) {
                    Z_vec.emplace_back(el.coord[2]);
                }
                bn_batch_invert<bn::Fp2>(Z_vec);

                const bn::Fp2 one = 1;

                for (size_t i = 0; i < vec.size(); ++i) {
                    bn::Fp2 Z2, Z3;
                    square(Z2, Z_vec[i]);
                    mul(Z3, Z2, Z_vec[i]);

                    mul(vec[i].coord[0], vec[i].coord[0], Z2);
                    mul(vec[i].coord[1], vec[i].coord[1], Z3);
                    vec[i].coord[2] = one;
                }
            }

        private:
            static value_type sqrt(const value_type &el) {
                return sqrt<fp2_type>(el);
            }

            static bn128_G2 G2_zero;
            static bn128_G2 G2_one;

            bn::Fp2 coord[3];

            typedef bn128_Fq base_field;
            typedef bn128_Fr scalar_field;
        };

        template<typename NumberType>
        bn128_G2 operator*(const NumberType &lhs, const bn128_G2 &rhs) {
            return scalar_mul<bn128_G2, m>(rhs, lhs);
        }

        template<typename NumberType, const NumberType &modulus_p>
        bn128_G2 operator*(const Fp_model<m, modulus_p> &lhs, const bn128_G2 &rhs) {
            return scalar_mul<bn128_G2, m>(rhs, lhs.as_bigint());
        }

    }    // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_FF_BN128_G2_HPP
