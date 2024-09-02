//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP
#define CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP

#include <type_traits>
#include <boost/tti/tti.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            BOOST_TTI_HAS_TYPE(commitment_type)
            BOOST_TTI_HAS_TYPE(proof_type)

            BOOST_TTI_MEMBER_TYPE(commitment_type)
            // BOOST_TTI_HAS_TYPE(proving_key)
            // BOOST_TTI_HAS_TYPE(verification_key)

            template<typename T>
            class has_available_static_member_function_commit {
                struct no { };

            protected:
                template<typename C>
                static void test(std::nullptr_t) {
                    struct t {
                        using C::commit;
                    };
                }

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            class has_available_static_member_function_proof_eval {
                struct no { };

            protected:
                template<typename C>
                static void test(std::nullptr_t) {
                    struct t {
                        using C::proof_eval;
                    };
                }

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            class has_available_static_member_function_verify_eval {
                struct no { };

            protected:
                template<typename C>
                static void test(std::nullptr_t) {
                    struct t {
                        using C::verify_eval;
                    };
                }

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            struct is_commitment {
                using commitment_type = typename member_type_commitment_type<T>::type;

                static const bool value = has_type_commitment_type<T>::value && has_type_proof_type<T>::value &&
                                          has_available_static_member_function_commit<T>::value &&
                                          has_available_static_member_function_proof_eval<T>::value &&
                                          has_available_static_member_function_verify_eval<T>::value;
                typedef T type;
            };

            // An idea was copied from this example:
            //    https://stackoverflow.com/questions/54920801/check-if-static-function-is-available-in-class-at-compile-time

            template<typename T, typename Enable = void>
            struct is_kzg_struct: std::false_type{
                static const bool value = false;
            };

            template<class T>
            struct is_kzg_struct<T, std::enable_if_t<std::is_invocable_r<bool, decltype(T::is_kzg)>::value>>
            : std::integral_constant<bool, T::is_kzg()>
            {};

            template<class T>
            constexpr bool is_kzg = is_kzg_struct<T>::value;


            template<typename T, typename Enable = void>
            struct is_lpc_struct: std::false_type{
                static const bool value = false;
            };

            template<class T>
            struct is_lpc_struct<T, std::enable_if_t<std::is_invocable_r<bool, decltype(T::is_lpc)>::value>>
            : std::integral_constant<bool, T::is_lpc()>
            {};

            template<class T>
            constexpr bool is_lpc = is_lpc_struct<T>::value;

            template<bool Condition, typename Type, std::size_t Size>
            struct select_container {
                using type = typename std::
                    conditional<Condition, std::array<Type, Size>, std::vector<Type>>::type;
            };
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_TYPE_TRAITS_HPP
