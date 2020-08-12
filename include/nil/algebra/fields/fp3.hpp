//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP3_HPP
#define ALGEBRA_FF_FP3_HPP

#include <nil/algebra/fields/fp2.hpp>
#include <nil/algebra/fields/element.hpp>

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            /**
             * Arithmetic in the field F[p^3].
             *
             * Let p := modulus. This interface provides arithmetic for the extension field
             * Fp3 = Fp[U]/(U^3-non_residue), where non_residue is in Fp.
             *
             * ASSUMPTION: p = 1 (mod 6)
             */
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct fp3 {
                typedef element<fp<ModulusBits, GeneratorBits>, number_type> non_residue_type;

                constexpr static const std::size_t modulus_bits = ModulusBits;
                typedef boost::multiprecision::number<
                    backends::cpp_int_backend<modulus_bits, modulus_bits, boost::multiprecision::unsigned_magnitude,
                                              boost::multiprecision::unchecked, void>>
                    modulus_type;

                constexpr static const std::size_t generator_bits = GeneratorBits;
                typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                    generator_bits, generator_bits, boost::multiprecision::unsigned_magnitude,
                    boost::multiprecision::unchecked, void>>
                    generator_type;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct element_fp3 : public element<fp3<ModulusBits, GeneratorBits>>  {

                using underlying_type = element<fp<ModulusBits, GeneratorBits>>;

                using type = std::array<underlying_type, 3>;

            private:

                type data;

            public:
                element_fp3(type data) : data(data);

                inline static element_fp3 zero() const {
                    return {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()};
                }

                inline static element_fp3 one() const {
                    return {underlying_type::one(), underlying_type::zero(), underlying_type::zero()};
                }

                bool is_zero() const {
                    return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero()) &&
                           (data[2] == underlying_type::zero());
                }

                bool operator==(const element_fp3 &B) const {
                    return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                }

                bool operator!=(const element_fp3 &B) const {
                    return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                }

                element_fp3 operator+(const element_fp3 &B) const {
                    return {data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]};
                }

                element_fp3 operator-(const element_fp3 &B) const {
                    return {data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]};
                }

                element_fp3 operator-() const {
                    return zero() - data;
                }

                element_fp3 operator*(const element_fp3 &B) const {
                    const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1],
                                          A2B2 = data[2] * B.data[2];

                    return {A0B0 + non_residue * (data[1] + data[2]) * (B.data[1] + B.data[2]) - A1B1 - A2B2,
                            (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1 + non_residue * A2B2,
                            (data[0] + data[2]) * (B.data[0] + B.data[2]) - A0B0 + A1B1 - A2B2};
                }

                element_fp3 sqrt() const {

                    // compute square root with Tonelli--Shanks
                }

                element_fp3 square() const {
                    return data * data;    // maybe can be done more effective
                }

                template<typename PowerType>
                element_fp3 pow(const PowerType &power) const {
                    return detail::power(data, power);
                }

                element_fp3 inverse() const {

                    /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                     * Algorithm 17 */

                    const underlying_type &A0 = data[0], &A1 = data[1], &A1 = data[2];

                    const underlying_type t0 = A0.square();
                    const underlying_type t1 = A1.square();
                    const underlying_type t2 = A2.square();
                    const underlying_type t3 = A0 * A1;
                    const underlying_type t4 = A0 * A2;
                    const underlying_type t5 = A1 * A2;
                    const underlying_type c0 = t0 - non_residue * t5;
                    const underlying_type c1 = non_residue * t2 - t3;
                    const underlying_type c2 =
                        t1 - t4;    // typo in paper referenced above. should be "-" as per Scott, but is "*"
                    const underlying_type t6 = (A0 * c0 + non_residue * (A2 * c1 + A1 * c2)).inverse();
                    return {t6 * c0, t6 * c1, t6 * c2};
                }
            };
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_HPP
