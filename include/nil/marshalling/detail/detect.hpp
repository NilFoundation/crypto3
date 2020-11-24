//---------------------------------------------------------------------------//
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_DETECT_HPP
#define MARSHALLING_DETECT_HPP

#include <type_traits>
#include <utility>

namespace nil {
    namespace marshalling {
        namespace detail {

            // VS2015 does NOT support expressions SFINAE, will use it for later versions.

            // template <typename... TArgs>
            // using VoidT = void;

            // template <typename TVoid, template <class...> class TOp, typename... TArgs>
            // struct PresenceDetector
            //{
            //    constexpr static const bool value = false;
            //};

            // template <template <class...> class TOp, typename... TArgs>
            // struct PresenceDetector<VoidT<TOp<TArgs...> >, TOp, TArgs...>
            //{
            //    constexpr static const bool value = true;
            //};

            // template <template <class...> class TOp, typename... TArgs>
            // constexpr bool isDetected()
            //{
            //    return PresenceDetector<void, TOp, TArgs...>::value;
            //}

            // template <typename T>
            // using HasClearOp = decltype(std::declval<T&>().clear());

            // template <typename T>
            // using HasReserveOp = decltype(std::declval<T&>().reserve(std::declval<typename T::size_type>()));

            template<typename T>
            class has_clear_func {
                struct no { };

            protected:
                template<typename C>
                static auto test(std::nullptr_t) -> decltype(std::declval<C>().clear());

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            class has_reserve_func {
                struct no { };

            protected:
                template<typename C>
                static auto test(std::nullptr_t) -> decltype(std::declval<C>().reserve(0U));

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            class has_resize_func {
                struct no { };

            protected:
                template<typename C>
                static auto test(std::nullptr_t) -> decltype(std::declval<C>().resize(0U));

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
            };

            template<typename T>
            class has_remove_suffix_func {
            protected:
                typedef char Yes;
                typedef unsigned no;

                template<typename U, U>
                struct ReallyHas;

                template<typename C>
                static Yes test(ReallyHas<void (C::*)(typename C::size_type), &C::remove_suffix> *);

                template<typename>
                static no test(...);

            public:
                constexpr static const bool value = (sizeof(test<T>(nullptr)) == sizeof(Yes));
            };

            template<class T, class R = void>
            struct enable_if_has_interface_options {
                using type = R;
            };

            template<class T, class Enable = void>
            struct has_interface_options {
                constexpr static const bool value = false;
            };

            template<class T>
            struct has_interface_options<
                T, typename enable_if_has_interface_options<typename T::interface_options_type>::type> {
                constexpr static const bool value = true;
            };

            template<class T, class R = void>
            struct enable_if_has_impl_options {
                using type = R;
            };

            template<class T, class Enable = void>
            struct has_impl_options {
                constexpr static const bool value = false;
            };

            template<class T>
            struct has_impl_options<T, typename enable_if_has_impl_options<typename T::impl_options_type>::type> {
                constexpr static const bool value = true;
            };
        }    // namespace detail
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_DETECT_HPP
