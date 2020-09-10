//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_G2_HPP
#define ALGEBRA_CURVES_BLS12_G2_HPP

#include <nil/algebra/curves/detail/bls12/basic_policy.hpp>

#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_g2 { };

                template<>
                struct bls12_g2<381, CHAR_BIT> {

                    using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<typename policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g2() :
                        bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                 underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g2(underlying_field_type_value X,
                             underlying_field_type_value Y,
                             underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
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

                        underlying_field_type_value Z1_squared = (this->p[2]).squared();
                        underlying_field_type_value Z2_squared = (other.p[2]).squared();

                        if ((this->p[0] * Z2_squared) != (other.p[0] * Z1_squared)) {
                            return false;
                        }

                        underlying_field_type_value Z1_cubed = (this->p[2]) * Z1_squared;
                        underlying_field_type_value Z2_cubed = (other.p[2]) * Z2_squared;

                        if ((this->p[1] * Z2_cubed) != (other.p[1] * Z1_cubed)) {
                            return false;
                        }

                        return true;
                    }

                    bool operator!=(const bls12_g2& other) const {
                        return !(operator==(other));
                    }

                    bool is_zero() const {
                        return (this->p[2].is_zero());
                    }

                    bls12_g2 operator+(const bls12_g2 &other) const {
                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // handle double case
                        if (this->operator==(other)) {
                            return this->doubled();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        underlying_field_type_value Z1Z1 = (this->p[2]).squared();             // Z1Z1 = Z1^2
                        underlying_field_type_value Z2Z2 = (other.p[2]).squared();             // Z2Z2 = Z2^2
                        underlying_field_type_value U1 = (this->p[0]) * Z2Z2;                  // U1 = X1 * Z2Z2
                        underlying_field_type_value U2 = (other.p[0]) * Z1Z1;                  // U2 = X2 * Z1Z1
                        underlying_field_type_value S1 = (this->p[1]) * (other.p[2]) * Z2Z2;      // S1 = Y1 * Z2 * Z2Z2
                        underlying_field_type_value S2 = (other.p[1]) * (this->p[2]) * Z1Z1;      // S2 = Y2 * Z1 * Z1Z1
                        underlying_field_type_value H = U2 - U1;                            // H = U2-U1
                        underlying_field_type_value S2_minus_S1 = S2-S1;
                        underlying_field_type_value I = (H+H).squared();                    // I = (2 * H)^2
                        underlying_field_type_value J = H * I;                              // J = H * I
                        underlying_field_type_value r = S2_minus_S1 + S2_minus_S1;          // r = 2 * (S2-S1)
                        underlying_field_type_value V = U1 * I;                             // V = U1 * I
                        underlying_field_type_value X3 = r.squared() - J - (V+V);           // X3 = r^2 - J - 2 * V
                        underlying_field_type_value S1_J = S1 * J;
                        underlying_field_type_value Y3 = r * (V-X3) - (S1_J+S1_J);          // Y3 = r * (V-X3)-2 S1 J
                        underlying_field_type_value Z3 = ((this->p[2]+other.p[2]).squared()-Z1Z1-Z2Z2) * H; // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                        return bls12_g2(X3, Y3, Z3);
                    }

                    bls12_g2 operator-() const {
                        return bls12_g2(this->p[0], -(this->p[1]), this->p[2]);
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

                        underlying_field_type_value A = (this->p[0]).squared();         // A = X1^2
                        underlying_field_type_value B = (this->p[1]).squared();        // B = Y1^2
                        underlying_field_type_value C = B.squared();                // C = B^2
                        underlying_field_type_value D = (this->p[0] + B).squared() - A - C;
                        D = D+D;                        // D = 2 * ((X1 + B)^2 - A - C)
                        underlying_field_type_value E = A + A + A;                  // E = 3 * A
                        underlying_field_type_value F = E.squared();                // F = E^2
                        underlying_field_type_value X3 = F - (D+D);                 // X3 = F - 2 D
                        underlying_field_type_value eightC = C+C;
                        eightC = eightC + eightC;
                        eightC = eightC + eightC;
                        underlying_field_type_value Y3 = E * (D - X3) - eightC;     // Y3 = E * (D - X3) - 8 * C
                        underlying_field_type_value Y1Z1 = (this->p[1])*(this->p[2]);
                        underlying_field_type_value Z3 = Y1Z1 + Y1Z1;               // Z3 = 2 * Y1 * Z1

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

                        const underlying_field_type_value Z1Z1 = (this->p[2]).squared();

                        const underlying_field_type_value &U1 = this->p[0];
                        const underlying_field_type_value U2 = other.p[0] * Z1Z1;

                        const underlying_field_type_value Z1_cubed = (this->p[2]) * Z1Z1;

                        const underlying_field_type_value &S1 = (this->p[1]);                // S1 = Y1 * Z2 * Z2Z2
                        const underlying_field_type_value S2 = (other.p[1]) * Z1_cubed;      // S2 = Y2 * Z1 * Z1Z1

                        if (U1 == U2 && S1 == S2) {
                            // dbl case; nothing of above can be reused
                            return this->doubled();
                        }


                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                        underlying_field_type_value H = U2-(this->p[0]);                         // H = U2-X1
                        underlying_field_type_value HH = H.squared() ;                        // HH = H&2
                        underlying_field_type_value I = HH+HH;                                // I = 4*HH
                        I = I + I;
                        underlying_field_type_value J = H*I;                                  // J = H*I
                        underlying_field_type_value r = S2-(this->p[1]);                         // r = 2*(S2-Y1)
                        r = r + r;
                        underlying_field_type_value V = (this->p[0]) * I ;                       // V = X1*I
                        underlying_field_type_value X3 = r.squared()-J-V-V;                   // X3 = r^2-J-2*V
                        underlying_field_type_value Y3 = (this->p[1])*J;                         // Y3 = r*(V-X3)-2*Y1*J
                        Y3 = r*(V-X3) - Y3 - Y3;
                        underlying_field_type_value Z3 = ((this->p[2])+H).squared() - Z1Z1 - HH; // Z3 = (Z1+H)^2-Z1Z1-HH

                        return bls12_g2(X3, Y3, Z3);
                    }

                    void to_affine_coordinates() {
                        if (this->is_zero()) {
                            this->p[0] = underlying_field_type_value::zero();
                            this->p[1] = underlying_field_type_value::one();
                            this->p[2] = underlying_field_type_value::zero();
                        }
                        else {
                            underlying_field_type_value Z_inv = Z.inversed();
                            underlying_field_type_value Z2_inv = Z_inv.squared();
                            underlying_field_type_value Z3_inv = Z2_inv * Z_inv;
                            this->p[0] = this->p[0] * Z2_inv;
                            this->p[1] = this->p[1] * Z3_inv;
                            this->p[2] = underlying_field_type_value::one();
                        }
                    }

                    void to_special() {
                        this->to_affine_coordinates();
                    }

                    bool is_special() const {
                        return (this->is_zero() || this->p[2] == underlying_field_type_value::one());
                    }
                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

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
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00);    //?

                    bls12_g2() :
                        bls12_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                 underlying_field_type_value::zero()) {};
                    // must be
                    // bls12_g2() : bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    bls12_g2(underlying_field_type_value X,
                             underlying_field_type_value Y,
                             underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
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

                        underlying_field_type_value Z1_squared = (this->p[2]).squared();
                        underlying_field_type_value Z2_squared = (other.p[2]).squared();

                        if ((this->p[0] * Z2_squared) != (other.p[0] * Z1_squared)) {
                            return false;
                        }

                        underlying_field_type_value Z1_cubed = (this->p[2]) * Z1_squared;
                        underlying_field_type_value Z2_cubed = (other.p[2]) * Z2_squared;

                        if ((this->p[1] * Z2_cubed) != (other.p[1] * Z1_cubed)) {
                            return false;
                        }

                        return true;
                    }

                    bool operator!=(const bls12_g2& other) const {
                        return !(operator==(other));
                    }

                    bool is_zero() const {
                        return (this->p[2].is_zero());
                    }

                    bls12_g2 operator+(const bls12_g2 &other) const {
                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // handle double case
                        if (this->operator==(other)) {
                            return this->doubled();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        underlying_field_type_value Z1Z1 = (this->p[2]).squared();             // Z1Z1 = Z1^2
                        underlying_field_type_value Z2Z2 = (other.p[2]).squared();             // Z2Z2 = Z2^2
                        underlying_field_type_value U1 = (this->p[0]) * Z2Z2;                  // U1 = X1 * Z2Z2
                        underlying_field_type_value U2 = (other.p[0]) * Z1Z1;                  // U2 = X2 * Z1Z1
                        underlying_field_type_value S1 = (this->p[1]) * (other.p[2]) * Z2Z2;      // S1 = Y1 * Z2 * Z2Z2
                        underlying_field_type_value S2 = (other.p[1]) * (this->p[2]) * Z1Z1;      // S2 = Y2 * Z1 * Z1Z1
                        underlying_field_type_value H = U2 - U1;                            // H = U2-U1
                        underlying_field_type_value S2_minus_S1 = S2-S1;
                        underlying_field_type_value I = (H+H).squared();                    // I = (2 * H)^2
                        underlying_field_type_value J = H * I;                              // J = H * I
                        underlying_field_type_value r = S2_minus_S1 + S2_minus_S1;          // r = 2 * (S2-S1)
                        underlying_field_type_value V = U1 * I;                             // V = U1 * I
                        underlying_field_type_value X3 = r.squared() - J - (V+V);           // X3 = r^2 - J - 2 * V
                        underlying_field_type_value S1_J = S1 * J;
                        underlying_field_type_value Y3 = r * (V-X3) - (S1_J+S1_J);          // Y3 = r * (V-X3)-2 S1 J
                        underlying_field_type_value Z3 = ((this->p[2]+other.p[2]).squared()-Z1Z1-Z2Z2) * H; // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                        return bls12_g2(X3, Y3, Z3);
                    }

                    bls12_g2 operator-() const {
                        return bls12_g2(this->p[0], -(this->p[1]), this->p[2]);
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

                        underlying_field_type_value A = (this->p[0]).squared();         // A = X1^2
                        underlying_field_type_value B = (this->p[1]).squared();        // B = Y1^2
                        underlying_field_type_value C = B.squared();                // C = B^2
                        underlying_field_type_value D = (this->p[0] + B).squared() - A - C;
                        D = D+D;                        // D = 2 * ((X1 + B)^2 - A - C)
                        underlying_field_type_value E = A + A + A;                  // E = 3 * A
                        underlying_field_type_value F = E.squared();                // F = E^2
                        underlying_field_type_value X3 = F - (D+D);                 // X3 = F - 2 D
                        underlying_field_type_value eightC = C+C;
                        eightC = eightC + eightC;
                        eightC = eightC + eightC;
                        underlying_field_type_value Y3 = E * (D - X3) - eightC;     // Y3 = E * (D - X3) - 8 * C
                        underlying_field_type_value Y1Z1 = (this->p[1])*(this->p[2]);
                        underlying_field_type_value Z3 = Y1Z1 + Y1Z1;               // Z3 = 2 * Y1 * Z1

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

                        const underlying_field_type_value Z1Z1 = (this->p[2]).squared();

                        const underlying_field_type_value &U1 = this->p[0];
                        const underlying_field_type_value U2 = other.p[0] * Z1Z1;

                        const underlying_field_type_value Z1_cubed = (this->p[2]) * Z1Z1;

                        const underlying_field_type_value &S1 = (this->p[1]);                // S1 = Y1 * Z2 * Z2Z2
                        const underlying_field_type_value S2 = (other.p[1]) * Z1_cubed;      // S2 = Y2 * Z1 * Z1Z1

                        if (U1 == U2 && S1 == S2) {
                            // dbl case; nothing of above can be reused
                            return this->doubled();
                        }


                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                        underlying_field_type_value H = U2-(this->p[0]);                         // H = U2-X1
                        underlying_field_type_value HH = H.squared() ;                        // HH = H&2
                        underlying_field_type_value I = HH+HH;                                // I = 4*HH
                        I = I + I;
                        underlying_field_type_value J = H*I;                                  // J = H*I
                        underlying_field_type_value r = S2-(this->p[1]);                         // r = 2*(S2-Y1)
                        r = r + r;
                        underlying_field_type_value V = (this->p[0]) * I ;                       // V = X1*I
                        underlying_field_type_value X3 = r.squared()-J-V-V;                   // X3 = r^2-J-2*V
                        underlying_field_type_value Y3 = (this->p[1])*J;                         // Y3 = r*(V-X3)-2*Y1*J
                        Y3 = r*(V-X3) - Y3 - Y3;
                        underlying_field_type_value Z3 = ((this->p[2])+H).squared() - Z1Z1 - HH; // Z3 = (Z1+H)^2-Z1Z1-HH

                        return bls12_g2(X3, Y3, Z3);
                    }

                    void to_affine_coordinates() {
                        if (this->is_zero()) {
                            this->p[0] = underlying_field_type_value::zero();
                            this->p[1] = underlying_field_type_value::one();
                            this->p[2] = underlying_field_type_value::zero();
                        }
                        else {
                            underlying_field_type_value Z_inv = Z.inversed();
                            underlying_field_type_value Z2_inv = Z_inv.squared();
                            underlying_field_type_value Z3_inv = Z2_inv * Z_inv;
                            this->p[0] = this->p[0] * Z2_inv;
                            this->p[1] = this->p[1] * Z3_inv;
                            this->p[2] = underlying_field_type_value::one();
                        }
                    }

                    void to_special() {
                        this->to_affine_coordinates();
                    }

                    bool is_special() const {
                        return (this->is_zero() || this->p[2] == underlying_field_type_value::one());
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
}    // namespace nil
#endif    // ALGEBRA_CURVES_BLS12_G2_HPP
