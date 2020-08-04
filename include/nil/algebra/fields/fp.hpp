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
        struct fp_policy {

            constexpr static const std::size_t modulus_bits = ModulusBits;
            typedef number<backends::cpp_int_backend<modulus_bits, modulus_bits, unsigned_magnitude, unchecked, void>>
                modulus_type;

            constexpr static const std::size_t generator_bits = GeneratorBits;
            typedef number<
                backends::cpp_int_backend<generator_bits, generator_bits, unsigned_magnitude, unchecked, void>>
                generator_type;

        };

        template<typename NumberType>
        struct fp {
            using type = NumberType;

            fp(type data) : data(data);

            inline static fp zero() const {
                return fp(type(0));
            }

            inline static fp one() const {
                return fp(type(1));
            }

            bool operator==(const fp &B) const {
                return data == B.data;
            }

            bool operator!=(const fp &B) const {
                return data != B.data;
            }

            fp operator+(const fp &B) const {
                return data + B.data;
            }

            fp operator-(const fp &B) const {
                return data - B.data;
            }

            fp operator*(const fp &B) const {
                return data * B.data;
            }

            fp sqrt() const {
                return sqrt(data);
            }

            fp square() const {
                return data * data;    // maybe can be done more effective
            }

            fp pow(const PowerType &power) const {
                return power(data, power);
            }

            fp invert() const {
                return invert(data);
            }

        private:
            type data;
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP_HPP
