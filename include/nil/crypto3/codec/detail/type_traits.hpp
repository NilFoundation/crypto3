//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CODEC_TYPE_TRAITS_HPP
#define CRYPTO3_CODEC_TYPE_TRAITS_HPP

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
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

                template<typename T>
                struct has_const_iterator {
                private:
                    typedef char one;
                    typedef struct {
                        char array[2];
                    } two;

                    template<typename C>
                    static one test(typename C::const_iterator *);

                    template<typename C>
                    static two test(...);

                public:
                    static const bool value = sizeof(test<T>(0)) == sizeof(one);
                    typedef T type;
                };

                template<typename T>
                struct has_begin_end {
                    struct Dummy {
                        typedef void const_iterator;
                    };
                    typedef typename std::conditional<has_const_iterator<T>::value, T, Dummy>::type TType;
                    typedef typename TType::const_iterator iter;

                    struct Fallback {
                        iter begin() const;

                        iter end() const;
                    };

                    struct Derived : TType, Fallback {};

                    template<typename C, C>
                    struct ChT;

                    template<typename C>
                    static char (&f(ChT<iter (Fallback::*)() const, &C::begin> *))[1];

                    template<typename C>
                    static char (&f(...))[2];

                    template<typename C>
                    static char (&g(ChT<iter (Fallback::*)() const, &C::end> *))[1];

                    template<typename C>
                    static char (&g(...))[2];

                    static bool const beg_value = sizeof(f<Derived>(0)) == 2;
                    static bool const end_value = sizeof(g<Derived>(0)) == 2;
                };

                template<typename T>
                struct is_container {
                    static const bool value =
                        has_const_iterator<T>::value && has_begin_end<T>::beg_value && has_begin_end<T>::end_value;
                };
            }    // namespace detail
        }        // namespace codec
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_TYPE_TRAITS_HPP
