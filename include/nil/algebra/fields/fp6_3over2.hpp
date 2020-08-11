//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP6_3OVER2_HPP
#define ALGEBRA_FF_FP6_3OVER2_HPP

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/fp.hpp>

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
                
        /**
         * Arithmetic in the finite field F[(p^2)^3].
         *
         * Let p := modulus. This interface provides arithmetic for the extension field
         * Fp6 = Fp2[V]/(V^3-non_residue) where non_residue is in Fp2.
         *
         * ASSUMPTION: p = 1 (mod 6)
         */
        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct fp6_3over2 {
            typedef element<fp2<ModulusBits, GeneratorBits>, number_type> non_residue_type;

            constexpr static const std::size_t modulus_bits = ModulusBits;
            typedef number<backends::cpp_int_backend<modulus_bits, modulus_bits, unsigned_magnitude, unchecked, void>>
                modulus_type;

            constexpr static const std::size_t generator_bits = GeneratorBits;
            typedef number<
                backends::cpp_int_backend<generator_bits, generator_bits, unsigned_magnitude, unchecked, void>>
                generator_type;
                
        };

        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct element<fp6_3over2<ModulusBits, GeneratorBits>> {


            using underlying_type = element<fp2<ModulusBits, GeneratorBits>>;

            using type = std::array<underlying_type, 3>;

        private:

            using value_type = element<fp6_3over2<ModulusBits, GeneratorBits>>;

            type data;

        public:

            value_type(type data) : data(data);

            inline static value_type zero() const {
                return {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()};
            }

            inline static value_type one() const {
                return {underlying_type::one(), underlying_type::zero(), underlying_type::zero()};
            }

            bool operator==(const value_type &B) const {
                return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
            }

            bool operator!=(const value_type &B) const {
                return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
            }

            value_type operator+(const value_type &B) const {
                return {data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]};
            }

            value_type operator-(const value_type &B) const {
                return {data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]};
            }

            value_type operator-() const {
                return zero()-data;
            }
            
            value_type operator*(const value_type &B) const {
                const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1], A2B2 = data[2] * B.data[2];

                return {A0B0 + mul_by_non_residue (( data[1] + data[2] ) * ( B.data[1] + B.data[2] ) - A1B1 - A2B2),
                            ( data[0] + data[1] ) * ( B.data[0] + B.data[1] ) - A0B0 - A1B1 + mul_by_non_residue (A2B2),
                            ( data[0] + data[2] ) * ( B.data[0] + B.data[2] ) - A0B0 + A1B1 - A2B2};
            }

            value_type sqrt() const {

                // compute square root with Tonelli--Shanks
            }

            value_type mul_Fp_b(const element<fp> &B){
                return {data[0], data[1].mul_Fp_0(b), data[2]};
            }

            value_type mul_Fp_c(const element<fp> &B){
                return {data[0], data[1], data[2].mul_Fp_0(b)};
            }

            value_type mulFp6_24_Fp_01(const element<fp> B*){
                return {data[0], data[1].mul_Fp_0(B[1]), data[2].mul_Fp_0(B[0])};
            }

            value_type square() const {
                return data*data;    // maybe can be done more effective
            }

            template <typename PowerType>
            value_type pow(const PowerType &power) const {
                return detail::power(data, power);
            }

            value_type inverse() const {
                
                /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"; Algorithm 17 */

                const underlying_type &A0 = data[0], &A1 = data[1], &A1 = data[2];

                const underlying_type t0 = A0.square();
                const underlying_type t1 = A1.square();
                const underlying_type t2 = A2.square();
                const underlying_type t3 = A0*A1;
                const underlying_type t4 = A0*A2;
                const underlying_type t5 = A1*A2;
                const underlying_type c0 = t0 - mul_by_non_residue(t5);
                const underlying_type c1 = mul_by_non_residue (t2) - t3;
                const underlying_type c2 = t1 - t4; // typo in paper referenced above. should be "-" as per Scott, but is "*"
                const underlying_type t6 = (A0 * c0 + mul_by_non_residue(A2 * c1 + A1 * c2)).inverse();
                return {t6 * c0, t6 * c1, t6 * c2};

            }

        private:
            inline static underlying_type mul_by_non_residue(const underlying_type &A){
                return {non_residue * A};
            }

        };
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP6_3OVER2_HPP
