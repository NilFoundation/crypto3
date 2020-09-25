//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_G2_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_G2_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/basic_policy.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                    struct bls12_g2 { };

                    template<>
                    struct bls12_g2<381, CHAR_BIT> {

                        using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type_value = g2_field_type_value;

                        constexpr static const std::size_t value_bits =  policy_type::g2_field_type::value_bits + 1;

                        underlying_field_type_value X;
                        underlying_field_type_value Y;
                        underlying_field_type_value Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        bls12_g2() :
                            bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                     underlying_field_type_value::zero()) {};
                        // must be
                        // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        bls12_g2(underlying_field_type_value X,
                                 underlying_field_type_value Y,
                                 underlying_field_type_value Z) {
                            X = X;
                            Y = Y;
                            Z = Z;
                        };

                        static bls12_g2 zero() {
                            return bls12_g2();
                        }

                        static bls12_g2 one() {
                            return bls12_g2(
                                underlying_field_type_value(
                                    0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                    0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                                underlying_field_type_value(
                                    0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                    0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379),
                                underlying_field_type_value::one());
                            // must be
                            // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const bls12_g2 &other) const {
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

                        bool operator!=(const bls12_g2 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_type_value::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        bls12_g2 operator=(const bls12_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        bls12_g2 operator+(const bls12_g2 &other) const {
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

                        bls12_g2 operator-() const {
                            return bls12_g2(this->X, -(this->Y), this->Z);
                        }

                        bls12_g2 operator-(const bls12_g2 &other) const {
                            return (*this) + (-other);
                        }

                        bls12_g2 doubled() const {
                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                        bls12_g2 mixed_add(const bls12_g2 &other) const {

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                    private:

                        bls12_g2 add (const bls12_g2 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                    public:

                        /*************************  Reducing operations  ***********************************/

                        bls12_g2 to_affine_coordinates() const {
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

                            return bls12_g2(p_out[0], p_out[1], p_out[2]);
                        }

                        bls12_g2 to_special() const {
                            return this->to_affine_coordinates();
                        }

                        /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                        /*constexpr static */ const g2_field_type_value twist = g2_field_type_value(
                            {g2_field_type_value::underlying_type::one(), g2_field_type_value::underlying_type::one()});

                        /*constexpr static */ const g2_field_type_value twist_coeff_b = b * twist;

                    private:
                        /*constexpr static const underlying_field_type_value zero_fill = {
                            underlying_field_type_value::zero(), underlying_field_type_value::one(),
                            underlying_field_type_value::zero()};

                        constexpr static const underlying_field_type_value one_fill = {
                            underlying_field_type_value(
                                0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                            underlying_field_type_value(
                                0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379),
                            underlying_field_type_value::one()};*/
                    };

                    template<>
                    struct bls12_g2<377, CHAR_BIT> {

                        using policy_type = bls12_basic_policy<377, CHAR_BIT>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type_value = g2_field_type_value;

                        constexpr static const std::size_t value_bits =  policy_type::g2_field_type::value_bits;

                        underlying_field_type_value X;
                        underlying_field_type_value Y;
                        underlying_field_type_value Z;

                        bls12_g2() :
                            bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                     underlying_field_type_value::zero()) {};
                        // must be
                        // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        bls12_g2(underlying_field_type_value X,
                                 underlying_field_type_value Y,
                                 underlying_field_type_value Z) {
                            X = X;
                            Y = Y;
                            Z = Z;
                        };

                        static bls12_g2 zero() {
                            return bls12_g2();
                        }

                        static bls12_g2 one() {
                            return bls12_g2(
                                underlying_field_type_value(
                                    0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                                    0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                                underlying_field_type_value(
                                    0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                                    0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                                underlying_field_type_value::one());
                            // must be
                            // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/
                        
                        bool operator==(const bls12_g2 &other) const {
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

                        bool operator!=(const bls12_g2 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_type_value::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        bls12_g2 operator=(const bls12_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }
                        
                        bls12_g2 operator+(const bls12_g2 &other) const {
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

                        bls12_g2 operator-() const {
                            return bls12_g2(this->X, -(this->Y), this->Z);
                        }

                        bls12_g2 operator-(const bls12_g2 &other) const {
                            return (*this) + (-other);
                        }

                        bls12_g2 doubled() const {
                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                        bls12_g2 mixed_add(const bls12_g2 &other) const {

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                    private:

                        bls12_g2 add(const bls12_g2 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

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

                            return bls12_g2(X3, Y3, Z3);
                        }

                    public:

                        /*************************  Reducing operations  ***********************************/

                        bls12_g2 to_affine_coordinates() const {
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

                            return bls12_g2(p_out[0], p_out[1], p_out[2]);
                        }

                        bls12_g2 to_special() const {
                            return this->to_affine_coordinates();
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                        /*constexpr static const underlying_field_type_value zero_fill = {
                            underlying_field_type_value::zero(), underlying_field_type_value::one(),
                            underlying_field_type_value::zero()};

                        constexpr static const underlying_field_type_value one_fill = {
                            underlying_field_type_value(
                                0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                                0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                            underlying_field_type_value(
                                0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                                0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                            underlying_field_type_value::one()};*/
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_CURVES_BLS12_G2_HPP
