//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP12_2OVER3OVER2_HPP
#define ALGEBRA_FF_FP12_2OVER3OVER2_HPP

#include <nil/algebra/fields/element.hpp>
#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
                
        /**
         * Arithmetic in the finite field F[((p^2)^3)^2].
         *
         * Let p := modulus. This interface provides arithmetic for the extension field
         * Fp12 = Fp6[W]/(W^2-V) where Fp6 = Fp2[V]/(V^3-non_residue) and non_residue is in Fp2
         *
         * ASSUMPTION: p = 1 (mod 6)
         */
        template<std::size_t ModulusBits, std::size_t GeneratorBits>
        struct fp12_2over3over2 {
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
        struct element<fp12_2over3over2<ModulusBits, GeneratorBits>> {


            using underlying_type = element<fp6_3over2<ModulusBits, GeneratorBits>>;

            using type = std::array<underlying_type, 2>;

        private:

            using value_type = element<fp12_2over3over2<ModulusBits, GeneratorBits>>;

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

            value_type operator-() const {
                return zero()-data;
            }
            
            value_type operator*(const value_type &B) const {
                const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                return {A0B0 + mul_by_non_residue(A1B1), (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1};
            }

            value_type sqrt() const {

                // compute square root with Tonelli--Shanks
            }

            value_type square() const {
                return data*data;    // maybe can be done more effective
            }

            template <typename PowerType>
            value_type pow(const PowerType &power) const {
                return detail::power(data, power);
            }

            value_type inverse() const {

                /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                 * Algorithm 8 */

                const underlying_type &A0 = data[0], &A1 = data[1];
                
                const underlying_type t0 = A0.square();
                const underlying_type t1 = A1.square();
                const underlying_type t2 = t0 - mul_by_non_residue(t1);
                const underlying_type t3 = t2.inverse();
                const underlying_type c0 = A0 * t3;
                const underlying_type c1 = -(A1 * t3);

                return {c0, c1};

            }

        private:
            inline static underlying_type mul_by_non_residue(const underlying_type &A){
                return {non_residue * A.data[2], A.data[1], A.data[0]};
            }
        };

        /*
            (a + bw) -> (a - bw) gammar
        */
        element<fp12_2over3over2> Frobenius(element<fp12_2over3over2> A) {
            /* this assumes (q-1)/6 is odd */
        
            z.a_.a_.a_ = A.a_.a_.a_;
            z.a_.b_.a_ = A.a_.b_.a_;
            z.a_.c_.a_ = A.a_.c_.a_;
            z.b_.a_.a_ = A.b_.a_.a_;
            z.b_.b_.a_ = A.b_.b_.a_;
            z.b_.c_.a_ = A.b_.c_.a_;
            
            z.a_.a_.b_ = -A.a_.a_.b_;
            z.a_.b_.b_ = -A.a_.b_.b_;
            z.a_.c_.b_ = -A.a_.c_.b_;
            z.b_.a_.b_ = -A.b_.a_.b_;
            z.b_.b_.b_ = -A.b_.b_.b_;
            z.b_.c_.b_ = -A.b_.c_.b_;

            z.a_.b_ *= Param::gammar[1];
            z.a_.c_ *= Param::gammar[3];

            z.b_.a_ *= Param::gammar[0];
            z.b_.b_ *= Param::gammar[2];
            z.b_.c_ *= Param::gammar[4];
        }

        /*
            gammar = c + dw
            a + bw -> t = (a - bw)(c + dw)
            ~t = (a + bw)(c - dw)
            ~t * (c + dw) = (a + bw) * ((c + dw)(c - dw))
            gammar2 = (c + dw)(c - dw) in Fp6
        */
        element<fp12_2over3over2> Frobenius2(element<fp12_2over3over2> A) {

            
            z.a_.a_ = A.a_.a_;
            
            z.a_.a_ = A.a_.a_;
            z.a_.b_ = A.a_.b_.mul_Fp_0(Param::gammar2[1].a_);
            z.a_.c_ = A.a_.c_.mul_Fp_0(Param::gammar2[3].a_);
            z.b_.a_ = A.b_.a_.mul_Fp_0(Param::gammar2[0].a_);
            z.b_.b_ = A.b_.b_.mul_Fp_0(Param::gammar2[2].a_);
            z.b_.c_ = A.b_.c_.mul_Fp_0(Param::gammar2[4].a_);
        }

        element<fp12_2over3over2> Frobenius3(element<fp12_2over3over2> A) {
            z.a_.a_.a_ =  A.a_.a_.a_;
            z.a_.b_.a_ =  A.a_.b_.a_;
            z.a_.c_.a_ =  A.a_.c_.a_;
            z.b_.a_.a_ =  A.b_.a_.a_;
            z.b_.b_.a_ =  A.b_.b_.a_;
            z.b_.c_.a_ =  A.b_.c_.a_;

            z.a_.a_.b_ = -A.a_.a_.b_;
            z.a_.b_.b_ = -A.a_.b_.b_;
            z.a_.c_.b_ = -A.a_.c_.b_;
            z.b_.a_.b_ = -A.b_.a_.b_;
            z.b_.b_.b_ = -A.b_.b_.b_;
            z.b_.c_.b_ = -A.b_.c_.b_;


            z.a_.b_ *= Param::gammar3[1];
            z.a_.c_ *= Param::gammar3[3];

            z.b_.a_ *= Param::gammar3[0];
            z.b_.b_ *= Param::gammar3[2];
            z.b_.c_ *= Param::gammar3[4];
        }

        /*
            @note destory *this
        */
        element<fp12_2over3over2> mapToCyclo(element<fp12_2over3over2> A){
            // (a + b*i) -> ((a - b*i) * (a + b*i)^(-1))^(q^2+1)
            //
            // See Beuchat page 9: raising to 6-th power is the same as
            // conjugation, so this entire function computes
            // z^((p^6-1) * (p^2+1))
            z.a_ = A.a_;
            z.b_ - A.b_;
            data = A.data.inverse();
            z *= A;
            z.Frobenius2(A);
            z *= A;
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP12_2OVER3OVER2_HPP
