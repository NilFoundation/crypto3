//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FFT_TYPE_TRAITS_HPP
#define CRYPTO3_ALGEBRA_FFT_TYPE_TRAITS_HPP

#include <boost/integer/static_log2.hpp>

#define GENERATE_HAS_MEMBER_TYPE(Type)                                                \
                                                                                      \
    template<class T>                                                                 \
    class HasMemberType_##Type {                                                      \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            struct Type { };                                                          \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(typename U::Type *);                                          \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##Type : public std::integral_constant<bool, HasMemberType_##Type<T>::RESULT> { };

#define GENERATE_HAS_MEMBER(member)                                                   \
                                                                                      \
    template<class T>                                                                 \
    class HasMember_##member {                                                        \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            int member;                                                               \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(decltype(U::member) *);                                       \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##member : public std::integral_constant<bool, HasMember_##member<T>::RESULT> { };

#define GENERATE_HAS_MEMBER_FUNCTION(Function, ...)                                  \
                                                                                     \
    template<typename T>                                                             \
    struct has_##Function {                                                          \
        struct Fallback {                                                            \
            void Function(##__VA_ARGS__);                                            \
        };                                                                           \
                                                                                     \
        struct Derived : Fallback { };                                               \
                                                                                     \
        template<typename C, C>                                                      \
        struct ChT;                                                                  \
                                                                                     \
        template<typename C>                                                         \
        static char (&f(ChT<void (Fallback::*)(##__VA_ARGS__), &C::Function> *))[1]; \
                                                                                     \
        template<typename C>                                                         \
        static char (&f(...))[2];                                                    \
                                                                                     \
        static bool const value = sizeof(f<Derived>(0)) == 2;                        \
    };

#define GENERATE_HAS_MEMBER_CONST_FUNCTION(Function, ...)                                  \
                                                                                           \
    template<typename T>                                                                   \
    struct has_##Function {                                                                \
        struct Fallback {                                                                  \
            void Function(##__VA_ARGS__) const;                                            \
        };                                                                                 \
                                                                                           \
        struct Derived : Fallback { };                                                     \
                                                                                           \
        template<typename C, C>                                                            \
        struct ChT;                                                                        \
                                                                                           \
        template<typename C>                                                               \
        static char (&f(ChT<void (Fallback::*)(##__VA_ARGS__) const, &C::Function> *))[1]; \
                                                                                           \
        template<typename C>                                                               \
        static char (&f(...))[2];                                                          \
                                                                                           \
        static bool const value = sizeof(f<Derived>(0)) == 2;                              \
    };

#define GENERATE_HAS_MEMBER_RETURN_FUNCTION(Function, ReturnType, ...)                       \
                                                                                             \
    template<typename T>                                                                     \
    struct has_##Function {                                                                  \
        struct Dummy {                                                                       \
            typedef void ReturnType;                                                         \
        };                                                                                   \
        typedef typename std::conditional<has_##ReturnType<T>::value, T, Dummy>::type TType; \
        typedef typename TType::ReturnType type;                                             \
                                                                                             \
        struct Fallback {                                                                    \
            type Function(##__VA_ARGS__);                                                    \
        };                                                                                   \
                                                                                             \
        struct Derived : TType, Fallback { };                                                \
                                                                                             \
        template<typename C, C>                                                              \
        struct ChT;                                                                          \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(ChT<type (Fallback::*)(##__VA_ARGS__), &C::Function> *))[1];         \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(...))[2];                                                            \
                                                                                             \
        static bool const value = sizeof(f<Derived>(0)) == 2;                                \
    };

#define GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(Function, ReturnType, ...)                 \
                                                                                             \
    template<typename T>                                                                     \
    struct has_##Function {                                                                  \
        struct Dummy {                                                                       \
            typedef void ReturnType;                                                         \
        };                                                                                   \
        typedef typename std::conditional<has_##ReturnType<T>::value, T, Dummy>::type TType; \
        typedef typename TType::ReturnType type;                                             \
                                                                                             \
        struct Fallback {                                                                    \
            type Function(##__VA_ARGS__) const;                                              \
        };                                                                                   \
                                                                                             \
        struct Derived : TType, Fallback { };                                                \
                                                                                             \
        template<typename C, C>                                                              \
        struct ChT;                                                                          \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(ChT<type (Fallback::*)(##__VA_ARGS__) const, &C::Function> *))[1];   \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(...))[2];                                                            \
                                                                                             \
        static bool const value = sizeof(f<Derived>(0)) == 2;                                \
    };

namespace nil {
    namespace crypto3 {
        namespace fft {
            namespace detail {

                using namespace nil::crypto3::algebra;

                /*template<typename FieldType, std::size_t m>
                struct is_basic_radix2_domain {
                    constexpr static bool const value =
                        (m > 1) && !(m & (m - 1)) &&
                        (boost::static_log2<m>::value <= fields::arithmetic_params<FieldType>::s);
                };

                template<typename FieldType, std::size_t m>
                struct is_extended_radix2_domain {
                    constexpr static bool const value =
                        (m > 1) && !(m & (m - 1)) &&
                        (boost::static_log2<m>::value == fields::arithmetic_params<FieldType>::s + 1);
                };

                template<typename FieldType, std::size_t m>
                struct is_step_radix2_domain {
                private:
                    constexpr static std::size_t const small_m = m - (1ul << (boost::static_log2<m>::value - 1));

                public:
                    constexpr static bool const value =
                        (m > 1) && (m & (m - 1)) &&
                        (boost::static_log2<m>::value <= fields::arithmetic_params<FieldType>::s) &&
                        !(small_m & (small_m - 1));
                };*/
            }    // namespace detail
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FFT_TYPE_TRAITS_HPP