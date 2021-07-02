//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

/// @file marshalling/generic_handler.h
/// This file contains definition of common handler.

#ifndef MARSHALLING_GENERIC_HANDLER_HPP
#define MARSHALLING_GENERIC_HANDLER_HPP

#include <tuple>
#include <type_traits>

#include <nil/marshalling/processing/tuple.hpp>

#include <nil/detail/type_traits.hpp>

namespace nil {
    namespace marshalling {

        /// @brief Generic common message handler.
        /// @details Will define virtual message handling functions for all the
        ///          messages bundled in TAll plus one to handle TDefault
        ///          type of message as default behaviour. The declaration of the
        ///          handling function is as following:
        ///          @code
        ///          virtual TRetType handle(ActualMessageType& msg);
        ///          @endcode
        ///          All the handling functions will upcast the message to TDefault and
        ///          call the default message handling function with signature:
        ///          @code
        ///          virtual TRetType handle(TDefault& msg);
        ///          @endcode
        ///          which does nothing. To override the handling behaviour just inherit
        ///          your handler from nil::marshalling::generic_handler and override the appropriate
        ///          function.
        /// @tparam TDefault Base class of all custom messages bundled in TAll.
        /// @tparam TAll All message types bundled in std::tuple that need to
        ///         be handled.
        /// @tparam TRetType Return type of the implemented handle() functions.
        /// @pre TAll is any variation of std::tuple
        /// @pre TDefault is a base class for all the custom messages in TAll.
        /// @note The default destructor is @b NOT virtual. To allow polymorphic delete
        ///     make sure to declare the destructor virtual in the inherited class.
        /// @headerfile nil/marshalling/generic_handler.h
        template<typename TDefault, typename TAll, typename TRetType = void>
        class generic_handler {
            static_assert(nil::detail::is_tuple<TAll>::value, "TAll must be std::tuple");

#ifdef FOR_DOXYGEN_DOC_ONLY
        public:
            /// @brief Return type of every handle() member function.
            using RetType = TRetType;

            /// @brief Handle message object
            /// @detail Does nothing, can be overridden in the derived class.
            virtual TRetType handle(TDefault &msg);

        protected:
            /// @brief Destructor
            /// @detail Although there are virtual functions, the destructor is @b NOT
            ///     virtual. The protected destructor prevents typedef of @ref generic_handler
            ///     and use it as actual handler class. To allow polymorphic delete
            ///     (destruction) make sure to declare the inherited destructor as
            ///     virtual.
            generic_handlerr() noexcept = default;
#endif
        };

        /// @cond SKIP_DOC
        template<typename TDefault,
                 typename T1,
                 typename T2,
                 typename T3,
                 typename T4,
                 typename T5,
                 typename T6,
                 typename T7,
                 typename T8,
                 typename T9,
                 typename T10,
                 typename... TRest,
                 typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, TRest...>, TRetType>
            : public generic_handler<TDefault, std::tuple<TRest...>> {
            using base_impl_type = generic_handler<TDefault, std::tuple<TRest...>>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T6 &msg) {
                static_assert(std::is_base_of<TDefault, T6>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T7 &msg) {
                static_assert(std::is_base_of<TDefault, T7>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T8 &msg) {
                static_assert(std::is_base_of<TDefault, T8>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T9 &msg) {
                static_assert(std::is_base_of<TDefault, T9>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T10 &msg) {
                static_assert(std::is_base_of<TDefault, T10>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        namespace detail {

            template<typename TDefault, typename TRetType>
            class generic_handler_base {
            public:
                using RetType = TRetType;

                virtual TRetType handle(TDefault &msg) {
                    // Nothing to do
                    static_cast<void>(msg);
                    using tag =
                        typename std::conditional<std::is_void<TRetType>::value,
                                                  void_return_tag,
                                                  typename std::conditional<std::is_lvalue_reference<TRetType>::value,
                                                                            reference_return_tag,
                                                                            value_return_tag>::type>::type;
                    return default_handle(tag());
                }

            private:
                struct void_return_tag { };
                struct reference_return_tag { };
                struct value_return_tag { };

                void default_handle(void_return_tag) {
                }

                TRetType default_handle(reference_return_tag) {
                    static typename std::decay<TRetType>::type Value;
                    return Value;
                }

                TRetType default_handle(value_return_tag) {
                    return typename std::decay<TRetType>::type();
                }
            };

        }    // namespace detail

        template<typename TDefault,
                 typename T1,
                 typename T2,
                 typename T3,
                 typename T4,
                 typename T5,
                 typename T6,
                 typename T7,
                 typename T8,
                 typename T9,
                 typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5, T6, T7, T8, T9>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T6 &msg) {
                static_assert(std::is_base_of<TDefault, T6>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T7 &msg) {
                static_assert(std::is_base_of<TDefault, T7>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T8 &msg) {
                static_assert(std::is_base_of<TDefault, T8>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T9 &msg) {
                static_assert(std::is_base_of<TDefault, T9>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault,
                 typename T1,
                 typename T2,
                 typename T3,
                 typename T4,
                 typename T5,
                 typename T6,
                 typename T7,
                 typename T8,
                 typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5, T6, T7, T8>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T6 &msg) {
                static_assert(std::is_base_of<TDefault, T6>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T7 &msg) {
                static_assert(std::is_base_of<TDefault, T7>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T8 &msg) {
                static_assert(std::is_base_of<TDefault, T8>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault,
                 typename T1,
                 typename T2,
                 typename T3,
                 typename T4,
                 typename T5,
                 typename T6,
                 typename T7,
                 typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5, T6, T7>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T6 &msg) {
                static_assert(std::is_base_of<TDefault, T6>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T7 &msg) {
                static_assert(std::is_base_of<TDefault, T7>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault,
                 typename T1,
                 typename T2,
                 typename T3,
                 typename T4,
                 typename T5,
                 typename T6,
                 typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5, T6>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T6 &msg) {
                static_assert(std::is_base_of<TDefault, T6>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename T1, typename T2, typename T3, typename T4, typename T5, typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4, T5>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T5 &msg) {
                static_assert(std::is_base_of<TDefault, T5>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename T1, typename T2, typename T3, typename T4, typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3, T4>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T4 &msg) {
                static_assert(std::is_base_of<TDefault, T4>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename T1, typename T2, typename T3, typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2, T3>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T3 &msg) {
                static_assert(std::is_base_of<TDefault, T3>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename T1, typename T2, typename TRetType>
        class generic_handler<TDefault, std::tuple<T1, T2>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

            virtual TRetType handle(T2 &msg) {
                static_assert(std::is_base_of<TDefault, T2>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename T1, typename TRetType>
        class generic_handler<TDefault, std::tuple<T1>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

            virtual TRetType handle(T1 &msg) {
                static_assert(std::is_base_of<TDefault, T1>::value,
                              "TDefault must be base class for every element in TAll");

                return this->handle(static_cast<TDefault &>(msg));
            }

        protected:
            ~generic_handler() noexcept = default;
        };

        template<typename TDefault, typename TRetType>
        class generic_handler<TDefault, std::tuple<>, TRetType>
            : public detail::generic_handler_base<TDefault, TRetType> {
            using base_impl_type = detail::generic_handler_base<TDefault, TRetType>;

        public:
            using base_impl_type::handle;

        protected:
            ~generic_handler() noexcept = default;
        };

        /// @endcond

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_GENERIC_HANDLER_HPP
