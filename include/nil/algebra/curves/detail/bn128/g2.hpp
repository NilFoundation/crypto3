//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_G2_HPP
#define ALGEBRA_CURVES_BN128_G2_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/bn128/fq.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct bn128_g2 {

                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<
                        fields::detail::arithmetic_params<fields::bn128_fq<g1_field_bits, CHAR_BIT>>>
                        g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp2<
                        fields::detail::arithmetic_params<fields::bn128_fq<g2_field_bits, CHAR_BIT>>>
                        g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    bn128_g2() : bn128_g2(underlying_field_type_value::one(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()) {};
                    //must be 
                    //bn128_g2() : bn128_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    //when constexpr fields will be finished

                    bn128_g2(underlying_field_type_value X,
                             underlying_field_type_value Y,
                             underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static bn128_g2 zero() {
                        return bn128_g2();
                    }

                    static bn128_g2 one() {
                        return bn128_g2(underlying_field_type_value(
                            0x21C1452BAD76CBAFD56F91BF61C4C7A4764793ABC7E62D2EB2382A21D01014DA_cppui254,
                            0x13F9579708C580632ECD7DCD6EE2E6FC20F597815A2792CC5128240A38EEBC15_cppui254),
                        underlying_field_type_value(
                            0x16CFE76F05CE1E4C043A5A50EE37E9B0ADD1E47D95E5250BA20538A3680892C_cppui254,
                            0x2D6532096CCA63300C3BA564B9BD9949DCDFB32C84AC6E2A065FD2334A7D09BE_cppui254),
                        underlying_field_type_value::one());
                        //must be 
                        //return bn128_g2(one_fill[0], one_fill[1], one_fill[2]);
                        //when constexpr fields will be finished
                    }

                    bool operator==(const bn128_g2 &other) const {
                        bn128_g2 t0 = normalize();
                        bn128_g2 t1 = other.normalize();
                        if (t0.is_zero()) {
                            if (t1.is_zero())
                                return true;
                            return false;
                        }
                        if (t1.is_zero())
                            return false;

                        return t0.p[0] == t1.p[0] && t0.p[1] == t1.p[1];
                    }

                    bool operator!=(const bn128_g2 &other) const {
                        return !operator==(other);
                    }

                    bool is_zero() const {
                        return p[2].is_zero();
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = (p[0], p[1], p[2]) + (other.p[0], other.p[1], other.p[2])
                    */
                    bn128_g2 operator+(const bn128_g2 &other) const {

                        bn128_g2 res = *this;

                        res += other;

                        return res;
                    }

                    bn128_g2 operator-(const bn128_g2 &other) const {

                        bn128_g2 res = *this;

                        res -= other;

                        return res;
                    }

                    bn128_g2 operator-() const {
                        return bn128_g2({p[0], -p[1], p[2]});
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = 2(p[0], p[1], p[2])
                    */
                    bn128_g2 doubled() const {
                        underlying_field_type_value p_out[3];

                        underlying_field_type_value A, B, C, D, E;
                        A = p[0].squared();
                        B = p[1].squared();
                        C = B.squared();
                        D = ((p[0] + B).squared() - A - C).doubled();
                        E = A.doubled() + A;

                        p_out[0] = E.squared() - D.doubled();
                        p_out[1] = E * (D - p_out[0]) - C.doubled().doubled().doubled();
                        p_out[2] = (p[1] * p[2]).doubled();

                        return bn128_g2(p_out[0], p_out[1], p_out[2]);
                    }

                    bn128_g2 operator+=(const bn128_g2 &other) {

                        if (p[2].is_zero()) {
                            return other;
                        }
                        if (other.p[2].is_zero()) {
                            return *this;
                        }
                        underlying_field_type_value Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, t3, r, V;

                        Z1Z1 = p[2].squared();
                        Z2Z2 = other.p[2].squared();
                        U1 = p[0] * Z2Z2;
                        U2 = other.p[0] * Z2Z2;

                        S1 = p[1] * other.p[2] * Z2Z2;
                        S2 = other.p[1] * p[2] * Z1Z1;

                        H = U2 - U1;
                        t3 = S2 - S1;

                        if (H.is_zero()) {
                            if (t3.is_zero()) {
                                return doubled();
                            } else {
                                p[2] = underlying_field_type_value::zero();    // not sure
                            }
                            return *this;
                        }

                        I = H.doubled().squared();
                        J = H * I;
                        r = t3.doubled();
                        V = U1 * I;
                        p[0] = r.squared() - J - V.doubled();
                        p[1] = r * (V - p[0]) - (S1 * J).doubled();
                        p[2] = ((p[2] + other.p[2]).squared() - Z1Z1 - Z2Z2) * H;

                        return *this;
                    }

                    bn128_g2 &operator-=(const bn128_g2 &other) {

                        *this += (-other);

                        return *this;
                    }

                    bn128_g2 mixed_add(const bn128_g2 &other) const {
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // check for doubling case

                        // using Jacobian pinates so:
                        // (X1:Y1:Z1) = (X2:Y2:Z2)
                        // iff
                        // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                        // iff
                        // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                        // we know that Z2 = 1

                        underlying_field_type_value Z1Z1 = this->p[2].squared();

                        underlying_field_type_value U2 = other.p[0] * Z1Z1;

                        underlying_field_type_value S2 = other.p[1] * this->p[2] * Z1Z1;
                        ;    // S2 = Y2*Z1*Z1Z1

                        if (this->p[0] == U2 && this->p[1] == S2) {
                            // dbl case; nothing of above can be reused
                            return this->doubled();
                        }

                        bn128_g2 result;
                        underlying_field_type_value H, HH, I, J, r, V;
                        // H = U2-X1
                        H = U2 - this->p[0];
                        // HH = H^2
                        HH = H.squared();
                        // I = 4*HH
                        I = HH.doubled().doubled();
                        // J = H*I
                        J = H * I;
                        // r = 2*(S2-Y1)
                        r = (S2 - this->p[1]).doubled();
                        // V = X1*I
                        V = this->p[0] * I;
                        // X3 = r^2-J-2*V
                        result.p[0] = r.squared() - J - V.doubled();
                        // Y3 = r*(V-X3)-2*Y1*J
                        result.p[1] = r * (V - result.p[0]) - (this->p[1] * J).doubled();
                        // Z3 = (Z1+H)^2-Z1Z1-HH
                        result.p[2] = (this->p[2] + H).squared() - Z1Z1 - HH;

                        return result;
                    }
                    /*
                        out = in * m
                        @param out [out] Jacobi coord (out[0], out[1], out[2])
                        @param in [in] Jacobi coord (in[0], in[1], in[2])
                        @param m [in] scalar
                        @note MSB first binary method.

                        @note don't use Fp as INT
                        the inner format of Fp is not compatible with mie::Vuint
                    */
                    template<typename NumberType>
                    bn128_g2 operator*(const NumberType N) const {
                        // return multi_exp(*this, N);
                        return *this;
                    }

                    template<class N>
                    bn128_g2 &operator*=(const N &y) {
                        bn128_g2 t = *this * y;

                        p[0] = t.p[0];
                        p[1] = t.p[1];
                        p[2] = t.p[2];

                        return *this;
                    }

                    bn128_g2 normalize() const {
                        underlying_field_type_value p_out[3];

                        if (is_zero() || p[2].is_one())
                            return *this;
                        underlying_field_type_value r, r2;
                        r = p[2].inversed();
                        r2 = r.squared();
                        p_out[0] = p[0] * r2;        // r2
                        p_out[1] = p[1] * r * r2;    // r3
                        p_out[2] = underlying_field_type_value::one();

                        return bn128_g2(p_out[0], p_out[1], p_out[2]);
                    }
                private:

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::one(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};*/

                    /*constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(
                            0x21C1452BAD76CBAFD56F91BF61C4C7A4764793ABC7E62D2EB2382A21D01014DA_cppui254,
                            0x13F9579708C580632ECD7DCD6EE2E6FC20F597815A2792CC5128240A38EEBC15_cppui254),
                        underlying_field_type_value(
                            0x16CFE76F05CE1E4C043A5A50EE37E9B0ADD1E47D95E5250BA20538A3680892C_cppui254,
                            0x2D6532096CCA63300C3BA564B9BD9949DCDFB32C84AC6E2A065FD2334A7D09BE_cppui254),
                        underlying_field_type_value::one()};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_G2_HPP
