//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP_HPP
#define ALGEBRA_FF_FP_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/exponentiation/exponentiation.hpp>

namespace nil {
    namespace algebra {
        /**
         * Arithmetic in the finite field F[p], for prime p of fixed length.
         *
         * This class implements Fp-arithmetic, for a large prime p, using a fixed number
         * of words. It is optimized for tight memory consumption, so the modulus p is
         * passed as a template parameter, to avoid per-element overheads.
         */
        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct fp {

            constexpr static const std::size_t modulus_bits = ModulusBits;
            typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                modulus_bits, modulus_bits, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked,
                void>>
                modulus_type;

            constexpr static const std::size_t generator_bits = GeneratorBits;
            typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_int_backend<
                generator_bits, generator_bits, boost::multiprecision::unsigned_magnitude,
                boost::multiprecision::unchecked, void>>
                generator_type;
        };

        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct element<fp<ModulusBits, GeneratorBits>> {

            typedef arithmetic_params<fp<ModulusBits, GeneratorBits>> params_type;

            typedef params_type::modulus_type modulus_type;

            using type = modulus_type;

        private:
            using value_type = element<fp<ModulusBits, GeneratorBits>>;

            type data;

        public:
            value_type(type data) : data(data);

            inline static value_type zero() const {
                return value_type(type(0));
            }

            inline static value_type one() const {
                return value_type(type(1));
            }

            bool is_zero() const {
                return data == type(0);
            }

            bool is_one() const {
                return data == type(1);
            }

            bool operator==(const value_type &B) const {
                return data == B.data;
            }

            bool operator!=(const value_type &B) const {
                return data != B.data;
            }

            value_type operator+(const value_type &B) const {
                return data + B.data;
            }

            value_type operator-(const value_type &B) const {
                return data - B.data;
            }

            value_type operator-() const {
                return -data;
            }

            value_type operator*(const value_type &B) const {
                return data * B.data;
            }

            value_type sqrt() const {
                return sqrt(data);
            }

            value_type square() const {
                return data * data;    // maybe can be done more effective
            }

            template<typename PowerType>
            value_type pow(const PowerType &power) const {
                return power(data, power);
            }

            value_type inverse() const {
                return invert(data);
            }
        };

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP_HPP
