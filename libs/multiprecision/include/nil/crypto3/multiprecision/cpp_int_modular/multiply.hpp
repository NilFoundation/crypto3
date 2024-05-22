///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains eval_multiply for cpp_int_modular_backend, which does nothing but converts it to cpp_int_backend and does the multiplication.
//

#ifndef CRYPTO3_MP_CPP_INT_MUL_HPP
#define CRYPTO3_MP_CPP_INT_MUL_HPP

namespace boost {
    namespace multiprecision {
        namespace backends {
            // Functions in this file should be called only for creation of montgomery and Barett params, calculation of inverse element and 
            // montgomery_reduce. Since these functions are relatively slow and are not called very often, we will not optimize them.
            // We do NOT care about the execution speed, and will just redirect calls to normal boost::cpp_int.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR void 
            eval_multiply(cpp_int_modular_backend<Bits1 + Bits2> &result,
                          const cpp_int_modular_backend<Bits1> &a,
                          const cpp_int_modular_backend<Bits2> &b) noexcept {
                result = a;
                // Call the lower function, we don't care about speed here.
                eval_multiply(result, b);
            }

            // If the second argument is trivial or not, we still assign it to the first the exact same way.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value
                >::type
            eval_multiply(cpp_int_modular_backend<Bits1> &result,
                          const cpp_int_modular_backend<Bits2> &a,
                          const boost::multiprecision::limb_type &b) noexcept {
                result = a;
                // Call the lower function, we don't care about speed here.
                eval_multiply(result, b);
            }


            template<unsigned Bits1>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value>::type
            eval_multiply(cpp_int_modular_backend<Bits1> &result,
                          const boost::multiprecision::limb_type &b) noexcept {
                boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int = result.to_cpp_int();
                boost::multiprecision::backends::eval_multiply(result_cpp_int, b);
                result.from_cpp_int(result_cpp_int);
            }

            // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!!!
            // Covers the case where the second operand is not trivial.
            // Redirects the call to normal boost::cpp_int. We do not care about speed here.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type
            eval_multiply(cpp_int_modular_backend<Bits1> &result,
                          const cpp_int_modular_backend<Bits2> &a) noexcept {
                boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int = result.to_cpp_int();
                boost::multiprecision::backends::eval_multiply(result_cpp_int, a.to_cpp_int());
                result.from_cpp_int(result_cpp_int);
            }

            // We need to specialize this for goldilock fields, where the second argument is trivial, while the first may not.
            // Caller is responsible for the result to fit in "Bits1" bits, we WILL NOT THROW!!!
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                !boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type
            eval_multiply(
                cpp_int_modular_backend<Bits1>& result,
                const cpp_int_modular_backend<Bits2>& o) noexcept
            {
                using cpp_int_type = boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>;
                cpp_int_type result_cpp_int = result.to_cpp_int();
                // Here we need cpp_int_type::limb_type to compile, otherwise it's ambiguous which function to call, boost has functions
                // for signed and unsigned.
                boost::multiprecision::backends::eval_multiply(result_cpp_int, boost::multiprecision::limb_type(*o.limbs())); 
                result.from_cpp_int(result_cpp_int);
            }

            // It looks to me boost has a bug with handling 'eval_multiply' for both arguments being trivial but of
            // different bit length, so we need to specialize this one here.
            // Caller is responsible for the result to fit in "Bits1" bits, we WILL NOT THROW!!!
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>::type
            eval_multiply(
                cpp_int_modular_backend<Bits1>& result,
                const cpp_int_modular_backend<Bits2>& o) noexcept
            {
               *result.limbs() *= *o.limbs();
            }

            // Multiplication with an unsigned integral type.
            template<unsigned Bits1, unsigned Bits2>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value &&
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value
                >::type
            eval_multiply(cpp_int_modular_backend<Bits1> &result,
                          const cpp_int_modular_backend<Bits2> &a,
                          const boost::multiprecision::limb_type &b) noexcept {
                result = a;
                // Call the lower function, we don't care about speed here.
                eval_multiply(result, b);
            }

            // Multiplication with an unsigned integral type.
            template<unsigned Bits1>
            inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                boost::multiprecision::backends::is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits1>>::value>::type
            eval_multiply(cpp_int_modular_backend<Bits1> &result,
                          const boost::multiprecision::limb_type &b) noexcept {
                *result.limbs() *= b;
            }


        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost


#endif 
