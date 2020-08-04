//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP2_HPP
#define ALGEBRA_FF_FP2_HPP

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {

        /**
         * Arithmetic in the field F[p^2].
         *
         * Let p := modulus. This interface provides arithmetic for the extension field
         * Fp2 = Fp[U]/(U^2-non_residue), where non_residue is in Fp.
         *
         * ASSUMPTION: p = 1 (mod 6)
         */
        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct fp2 {
            typedef fp<number_type> non_residue_type;

            constexpr static const std::size_t modulus_bits = ModulusBits;
            typedef number<backends::cpp_int_backend<modulus_bits, modulus_bits, unsigned_magnitude, unchecked, void>>
                modulus_type;

            constexpr static const std::size_t generator_bits = GeneratorBits;
            typedef number<
                backends::cpp_int_backend<generator_bits, generator_bits, unsigned_magnitude, unchecked, void>>
                generator_type;

        };
        

        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct element<fp2<ModulusBits, GeneratorBits>> {


            using underlying_type = element<fp<ModulusBits, GeneratorBits>>;

            using type = std::array<underlying_type, 2>;

        private:

            using value_type = element<fp2<ModulusBits, GeneratorBits>>;

            type data;

        public:

            value_type(type data) : data(data);

            inline static value_type zero() const {
                return {underlying_type::zero(), underlying_type::zero()};
            }

            inline static value_type one() const {
                return {underlying_type::one(), underlying_type::zero()};
            }

            bool operator==(const value_type &B) const {
                return (data[0] == B.data[0]) && (data[1] == B.data[1]);
            }

            bool operator!=(const value_type &B) const {
                return (data[0] != B.data[0]) || (data[1] != B.data[1]);
            }

            value_type operator+(const value_type &B) const {
                return {data[0] + B.data[0], data[1] + B.data[1]};
            }

            value_type operator-(const value_type &B) const {
                return {data[0] - B.data[0], data[1] - B.data[1]};
            }

            value_type operator*(const value_type &B) const {
                const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                return {A0B0 + non_residue * A1B1, (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1};
            }

            value_type sqrt() const {

                // compute square root with Tonelli--Shanks
            }

            value_type square() const {
                return data*data;    // maybe can be done more effective
            }

            template <typename PowerType>
            value_type pow(const PowerType &power) const {
            }

            value_type inverse() const {

                /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                 * Algorithm 8 */

                const underlying_type &A0 = data[0], &A1 = data[1];
                
                const underlying_type t0 = A0.square();
                const underlying_type t1 = A1.square();
                const underlying_type t2 = t0 - non_residue * t1;
                const underlying_type t3 = t2.inverse();
                const underlying_type c0 = A0 * t3;
                const underlying_type c1 = -(A1 * t3);

                return {c0, c1};

            }

        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_HPP
