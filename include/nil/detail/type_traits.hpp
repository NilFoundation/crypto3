//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef NIL_DETAIL_TYPE_TRAITS_HPP
#define NIL_DETAIL_TYPE_TRAITS_HPP

#include <complex>

#include <iterator>
#include <tuple>

#include <boost/tti/tti.hpp>

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
    namespace detail {

        GENERATE_HAS_MEMBER_TYPE(iterator)
        GENERATE_HAS_MEMBER_TYPE(const_iterator)

        GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(begin, const_iterator)
        GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(end, const_iterator)
        
        template<typename T>
        struct is_iterator {
            static char test(...);

            template<typename U, typename = typename std::iterator_traits<U>::difference_type,
                     typename = typename std::iterator_traits<U>::pointer,
                     typename = typename std::iterator_traits<U>::reference,
                     typename = typename std::iterator_traits<U>::value_type,
                     typename = typename std::iterator_traits<U>::iterator_category>
            static long test(U &&);

            constexpr static bool value = std::is_same<decltype(test(std::declval<T>())), long>::value;
        };

        template<typename Range>
        struct is_range {
            static const bool value = has_begin<Range>::value && has_end<Range>::value;
        };

        template<typename Container>
        struct is_container {
            static const bool value
                = has_const_iterator<Container>::value && has_begin<Container>::value && has_end<Container>::value;
        };

        /// @brief Check whether provided type is a variant of
        ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
        /// @tparam TType Type to check.
        template<typename TType>
        struct is_tuple {
            /// @brief By default Value has value false. Will be true for any
            /// variant of <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename... TArgs>
        struct is_tuple<std::tuple<TArgs...>> {
            static const bool value = true;
        };
        /// @endcond

        //----------------------------------------

        /// @brief Check whether TType type is included in the tuple TTuple
        /// @tparam TType Type to check
        /// @tparam TTuple Tuple
        /// @pre @code IsTuple<TTuple>::value == true @endcode
        template<typename TType, typename TTuple>
        class is_in_tuple {
            static_assert(is_tuple<TTuple>::value, "TTuple must be std::tuple");

        public:
            /// @brief By default the value is false, will be set to true if TType
            ///     is found in TTuple.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename TType, typename TFirst, typename... TRest>
        class is_in_tuple<TType, std::tuple<TFirst, TRest...>> {
        public:
            static const bool value
                = std::is_same<TType, TFirst>::value || is_in_tuple<TType, std::tuple<TRest...>>::value;
        };

        template<typename TType>
        class is_in_tuple<TType, std::tuple<>> {
        public:
            static const bool value = false;
        };

        /// @endcond
    }    // namespace detail
}    // namespace nil

#endif    // NIL_DETAIL_TYPE_TRAITS_HPP
