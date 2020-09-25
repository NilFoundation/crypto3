//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_G1_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_G1_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/basic_policy.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                    struct bls12_g1 { };

                    template<>
                    struct bls12_g1<381, CHAR_BIT> {

                        using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type_value = g1_field_type_value;

                        constexpr static const std::size_t value_bits =  policy_type::g1_field_type::value_bits + 1;

                        underlying_field_type_value X;
                        underlying_field_type_value Y;
                        underlying_field_type_value Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        bls12_g1() :
                            bls12_g1(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                     underlying_field_type_value::zero()) {};
                        // must be
                        // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        bls12_g1(underlying_field_type_value X,
                                 underlying_field_type_value Y,
                                 underlying_field_type_value Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        static bls12_g1 zero() {
                            return bls12_g1();
                        }

                        static bls12_g1 one() {
                            return bls12_g1(
                                underlying_field_type_value(
                                    0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381),
                                underlying_field_type_value(
                                    0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380),
                                underlying_field_type_value::one());
                            // must be
                            // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const bls12_g1 &other) const {
                            if (this->is_zero()) {
                                return other.is_zero();
                            }

                            if (other.is_zero()) {
                                return false;
                            }

                            /* now neither is O */

                            // using Jacobian coordinates so:
                            // (X1:Y1:Z1) = (X2:Y2:Z2)
                            // iff
                            // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                            // iff
                            // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                            underlying_field_type_value Z1_squared = (this->Z).squared();
                            underlying_field_type_value Z2_squared = (other.Z).squared();

                            if ((this->X * Z2_squared) != (other.X * Z1_squared)) {
                                return false;
                            }

                            underlying_field_type_value Z1_cubed = (this->Z) * Z1_squared;
                            underlying_field_type_value Z2_cubed = (other.Z) * Z2_squared;

                            if ((this->Y * Z2_cubed) != (other.Y * Z1_cubed)) {
                                return false;
                            }

                            return true;
                        }

                        bool operator!=(const bls12_g1 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_type_value::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        bls12_g1 operator=(const bls12_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        bls12_g1 operator+(const bls12_g1 &other) const {
                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return (*this);
                            }

                            if (*this == other) {
                                return this->doubled();
                            }

                            return this->add(other);
                        }

                        bls12_g1 operator-() const {
                            return bls12_g1(this->X, -(this->Y), this->Z);
                        }

                        bls12_g1 operator-(const bls12_g1 &other) const {
                            return (*this) + (-other);
                        }

                        bls12_g1 doubled() const {

                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // no need to handle points of order 2,4
                            // (they cannot exist in a prime-order subgroup)

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                            underlying_field_type_value A = (this->X).squared();    // A = X1^2
                            underlying_field_type_value B = (this->Y).squared();    // B = Y1^2
                            underlying_field_type_value C = B.squared();               // C = B^2
                            underlying_field_type_value D = (this->X + B).squared() - A - C;
                            D = D + D;                                       // D = 2 * ((X1 + B)^2 - A - C)
                            underlying_field_type_value E = A + A + A;       // E = 3 * A
                            underlying_field_type_value F = E.squared();     // F = E^2
                            underlying_field_type_value X3 = F - (D + D);    // X3 = F - 2 D
                            underlying_field_type_value eightC = C + C;
                            eightC = eightC + eightC;
                            eightC = eightC + eightC;
                            underlying_field_type_value Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            underlying_field_type_value Y1Z1 = (this->Y) * (this->Z);
                            underlying_field_type_value Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return bls12_g1(X3, Y3, Z3);
                        }

                        bls12_g1 mixed_add(const bls12_g1 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
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

                            const underlying_field_type_value Z1Z1 = (this->Z).squared();

                            const underlying_field_type_value &U1 = this->X;
                            const underlying_field_type_value U2 = other.X * Z1Z1;

                            const underlying_field_type_value Z1_cubed = (this->Z) * Z1Z1;

                            const underlying_field_type_value &S1 = (this->Y);              // S1 = Y1 * Z2 * Z2Z2
                            const underlying_field_type_value S2 = (other.Y) * Z1_cubed;    // S2 = Y2 * Z1 * Z1Z1

                            if (U1 == U2 && S1 == S2) {
                                // dbl case; nothing of above can be reused
                                return this->doubled();
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                            underlying_field_type_value H = U2 - (this->X);    // H = U2-X1
                            underlying_field_type_value HH = H.squared();         // HH = H&2
                            underlying_field_type_value I = HH + HH;              // I = 4*HH
                            I = I + I;
                            underlying_field_type_value J = H * I;                // J = H*I
                            underlying_field_type_value r = S2 - (this->Y);    // r = 2*(S2-Y1)
                            r = r + r;
                            underlying_field_type_value V = (this->X) * I;            // V = X1*I
                            underlying_field_type_value X3 = r.squared() - J - V - V;    // X3 = r^2-J-2*V
                            underlying_field_type_value Y3 = (this->Y) * J;           // Y3 = r*(V-X3)-2*Y1*J
                            Y3 = r * (V - X3) - Y3 - Y3;
                            underlying_field_type_value Z3 =
                                ((this->Z) + H).squared() - Z1Z1 - HH;    // Z3 = (Z1+H)^2-Z1Z1-HH

                            return bls12_g1(X3, Y3, Z3);
                        }

                    private:

                        bls12_g1 add (const bls12_g1 &other) const {
                            
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                            underlying_field_type_value Z1Z1 = (this->Z).squared();    // Z1Z1 = Z1^2
                            underlying_field_type_value Z2Z2 = (other.Z).squared();    // Z2Z2 = Z2^2
                            underlying_field_type_value U1 = (this->X) * Z2Z2;         // U1 = X1 * Z2Z2
                            underlying_field_type_value U2 = (other.X) * Z1Z1;         // U2 = X2 * Z1Z1
                            underlying_field_type_value S1 =
                                (this->Y) * (other.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            underlying_field_type_value S2 =
                                (other.Y) * (this->Z) * Z1Z1;     // S2 = Y2 * Z1 * Z1Z1
                            underlying_field_type_value H = U2 - U1;    // H = U2-U1
                            underlying_field_type_value S2_minus_S1 = S2 - S1;
                            underlying_field_type_value I = (H + H).squared();             // I = (2 * H)^2
                            underlying_field_type_value J = H * I;                         // J = H * I
                            underlying_field_type_value r = S2_minus_S1 + S2_minus_S1;     // r = 2 * (S2-S1)
                            underlying_field_type_value V = U1 * I;                        // V = U1 * I
                            underlying_field_type_value X3 = r.squared() - J - (V + V);    // X3 = r^2 - J - 2 * V
                            underlying_field_type_value S1_J = S1 * J;
                            underlying_field_type_value Y3 = r * (V - X3) - (S1_J + S1_J);    // Y3 = r * (V-X3)-2 S1 J
                            underlying_field_type_value Z3 = ((this->Z + other.Z).squared() - Z1Z1 - Z2Z2) *
                                                             H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                            return bls12_g1(X3, Y3, Z3);
                        }

                    public:

                        /*************************  Reducing operations  ***********************************/

                        bls12_g1 to_affine_coordinates() const {
                            underlying_field_type_value p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_type_value::zero();
                                p_out[1] = underlying_field_type_value::one();
                                p_out[2] = underlying_field_type_value::zero();
                            } else {
                                underlying_field_type_value Z_inv = this->Z.inversed();
                                underlying_field_type_value Z2_inv = Z_inv.squared();
                                underlying_field_type_value Z3_inv = Z2_inv * Z_inv;
                                p_out[0] = this->X * Z2_inv;
                                p_out[1] = this->Y * Z3_inv;
                                p_out[2] = underlying_field_type_value::one();
                            }

                            return bls12_g1(p_out[0], p_out[1], p_out[2]);
                        }

                        bls12_g1 to_special() const {
                            return this->to_affine_coordinates();
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                        /*constexpr static const underlying_field_type_value zero_fill = {
                            underlying_field_type_value::zero(), underlying_field_type_value::one(),
                            underlying_field_type_value::zero()};

                        constexpr static const underlying_field_type_value one_fill = {
                            underlying_field_type_value(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381),
                            underlying_field_type_value(0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380),
                            underlying_field_type_value::one()};*/
                    };

                    template<>
                    struct bls12_g1<377, CHAR_BIT> {

                        using policy_type = bls12_basic_policy<377, CHAR_BIT>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type_value = g1_field_type_value;

                        constexpr static const std::size_t value_bits =  policy_type::g1_field_type::value_bits;

                        underlying_field_type_value X;
                        underlying_field_type_value Y;
                        underlying_field_type_value Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        bls12_g1() :
                            bls12_g1(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                     underlying_field_type_value::zero()) {};
                        // must be
                        // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        bls12_g1(underlying_field_type_value X,
                                 underlying_field_type_value Y,
                                 underlying_field_type_value Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        static bls12_g1 zero() {
                            return bls12_g1();
                        }

                        static bls12_g1 one() {
                            return bls12_g1(
                                underlying_field_type_value(
                                    0x8848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF_cppui376),
                                underlying_field_type_value(
                                    0x1914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6_cppui377),
                                underlying_field_type_value::one());
                            // must be
                            // bls12_g1() : bls12_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const bls12_g1 &other) const {
                            if (this->is_zero()) {
                                return other.is_zero();
                            }

                            if (other.is_zero()) {
                                return false;
                            }

                            /* now neither is O */

                            // using Jacobian coordinates so:
                            // (X1:Y1:Z1) = (X2:Y2:Z2)
                            // iff
                            // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                            // iff
                            // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                            underlying_field_type_value Z1_squared = (this->Z).squared();
                            underlying_field_type_value Z2_squared = (other.Z).squared();

                            if ((this->X * Z2_squared) != (other.X * Z1_squared)) {
                                return false;
                            }

                            underlying_field_type_value Z1_cubed = (this->Z) * Z1_squared;
                            underlying_field_type_value Z2_cubed = (other.Z) * Z2_squared;

                            if ((this->Y * Z2_cubed) != (other.Y * Z1_cubed)) {
                                return false;
                            }

                            return true;
                        }

                        bool operator!=(const bls12_g1 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_type_value::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        bls12_g1 operator=(const bls12_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        bls12_g1 operator+(const bls12_g1 &other) const {
                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return (*this);
                            }

                            if (*this == other) {
                                return this->doubled();
                            }

                            return this->add(other);
                        }

                        bls12_g1 operator-() const {
                            return bls12_g1(this->X, -(this->Y), this->Z);
                        }

                        bls12_g1 operator-(const bls12_g1 &other) const {
                            return (*this) + (-other);
                        }

                        bls12_g1 doubled() const {

                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // no need to handle points of order 2,4
                            // (they cannot exist in a prime-order subgroup)

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                            underlying_field_type_value A = (this->X).squared();    // A = X1^2
                            underlying_field_type_value B = (this->Y).squared();    // B = Y1^2
                            underlying_field_type_value C = B.squared();               // C = B^2
                            underlying_field_type_value D = (this->X + B).squared() - A - C;
                            D = D + D;                                       // D = 2 * ((X1 + B)^2 - A - C)
                            underlying_field_type_value E = A + A + A;       // E = 3 * A
                            underlying_field_type_value F = E.squared();     // F = E^2
                            underlying_field_type_value X3 = F - (D + D);    // X3 = F - 2 D
                            underlying_field_type_value eightC = C + C;
                            eightC = eightC + eightC;
                            eightC = eightC + eightC;
                            underlying_field_type_value Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            underlying_field_type_value Y1Z1 = (this->Y) * (this->Z);
                            underlying_field_type_value Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return bls12_g1(X3, Y3, Z3);
                        }

                        bls12_g1 mixed_add(const bls12_g1 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
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

                            const underlying_field_type_value Z1Z1 = (this->Z).squared();

                            const underlying_field_type_value &U1 = this->X;
                            const underlying_field_type_value U2 = other.X * Z1Z1;

                            const underlying_field_type_value Z1_cubed = (this->Z) * Z1Z1;

                            const underlying_field_type_value &S1 = (this->Y);              // S1 = Y1 * Z2 * Z2Z2
                            const underlying_field_type_value S2 = (other.Y) * Z1_cubed;    // S2 = Y2 * Z1 * Z1Z1

                            if (U1 == U2 && S1 == S2) {
                                // dbl case; nothing of above can be reused
                                return this->doubled();
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                            underlying_field_type_value H = U2 - (this->X);    // H = U2-X1
                            underlying_field_type_value HH = H.squared();         // HH = H&2
                            underlying_field_type_value I = HH + HH;              // I = 4*HH
                            I = I + I;
                            underlying_field_type_value J = H * I;                // J = H*I
                            underlying_field_type_value r = S2 - (this->Y);    // r = 2*(S2-Y1)
                            r = r + r;
                            underlying_field_type_value V = (this->X) * I;            // V = X1*I
                            underlying_field_type_value X3 = r.squared() - J - V - V;    // X3 = r^2-J-2*V
                            underlying_field_type_value Y3 = (this->Y) * J;           // Y3 = r*(V-X3)-2*Y1*J
                            Y3 = r * (V - X3) - Y3 - Y3;
                            underlying_field_type_value Z3 =
                                ((this->Z) + H).squared() - Z1Z1 - HH;    // Z3 = (Z1+H)^2-Z1Z1-HH

                            return bls12_g1(X3, Y3, Z3);
                        }

                    private:

                        bls12_g1 add(const bls12_g1 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                            underlying_field_type_value Z1Z1 = (this->Z).squared();    // Z1Z1 = Z1^2
                            underlying_field_type_value Z2Z2 = (other.Z).squared();    // Z2Z2 = Z2^2
                            underlying_field_type_value U1 = (this->X) * Z2Z2;         // U1 = X1 * Z2Z2
                            underlying_field_type_value U2 = (other.X) * Z1Z1;         // U2 = X2 * Z1Z1
                            underlying_field_type_value S1 =
                                (this->Y) * (other.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            underlying_field_type_value S2 =
                                (other.Y) * (this->Z) * Z1Z1;     // S2 = Y2 * Z1 * Z1Z1
                            underlying_field_type_value H = U2 - U1;    // H = U2-U1
                            underlying_field_type_value S2_minus_S1 = S2 - S1;
                            underlying_field_type_value I = (H + H).squared();             // I = (2 * H)^2
                            underlying_field_type_value J = H * I;                         // J = H * I
                            underlying_field_type_value r = S2_minus_S1 + S2_minus_S1;     // r = 2 * (S2-S1)
                            underlying_field_type_value V = U1 * I;                        // V = U1 * I
                            underlying_field_type_value X3 = r.squared() - J - (V + V);    // X3 = r^2 - J - 2 * V
                            underlying_field_type_value S1_J = S1 * J;
                            underlying_field_type_value Y3 = r * (V - X3) - (S1_J + S1_J);    // Y3 = r * (V-X3)-2 S1 J
                            underlying_field_type_value Z3 = ((this->Z + other.Z).squared() - Z1Z1 - Z2Z2) *
                                                             H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                            return bls12_g1(X3, Y3, Z3);
                        }

                    public:

                        /*************************  Reducing operations  ***********************************/

                        bls12_g1 to_affine_coordinates() const {
                            underlying_field_type_value p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_type_value::zero();
                                p_out[1] = underlying_field_type_value::one();
                                p_out[2] = underlying_field_type_value::zero();
                            } else {
                                underlying_field_type_value Z_inv = this->Z.inversed();
                                underlying_field_type_value Z2_inv = Z_inv.squared();
                                underlying_field_type_value Z3_inv = Z2_inv * Z_inv;
                                p_out[0] = this->X * Z2_inv;
                                p_out[1] = this->Y * Z3_inv;
                                p_out[2] = underlying_field_type_value::one();
                            }

                            return bls12_g1(p_out[0], p_out[1], p_out[2]);
                        }

                        bls12_g1 to_special() const {
                            return this->to_affine_coordinates();
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                        /*constexpr static const underlying_field_type_value zero_fill = {
                            underlying_field_type_value::zero(), underlying_field_type_value::one(),
                            underlying_field_type_value::zero()};

                        constexpr static const underlying_field_type_value one_fill = {
                            underlying_field_type_value(0x8848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF_cppui376),
                            underlying_field_type_value(0x1914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6_cppui377),
                            underlying_field_type_value::one()};*/
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_CURVES_BLS12_G1_HPP
