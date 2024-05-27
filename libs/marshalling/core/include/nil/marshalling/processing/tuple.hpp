//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
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

#ifndef MARSHALLING_PROCESSING_TUPLE_HPP
#define MARSHALLING_PROCESSING_TUPLE_HPP

#include <tuple>
#include <utility>
#include <type_traits>

#include <nil/detail/type_traits.hpp>

#include <nil/marshalling/assert_type.hpp>
#include <nil/marshalling/processing/aligned_union.hpp>

namespace nil {
    namespace marshalling {
        namespace processing {

            /// @brief Calculated "aligned union" storage type for all the types in
            ///     provided tuple.
            /// @tparam TTuple Tuple
            /// @pre @code IsTuple<TTuple>::value == true @endcode
            template<typename TTuple>
            struct tuple_as_aligned_union {
                /// @cond DOCUMENT_STATIC_ASSERT
                static_assert(nil::detail::is_tuple<TTuple>::value, "TTuple must be std::tuple");
                /// @endcond

                /// @brief Type definition is invalid for any type that is not
                ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>,
                ///     will be specialised to proper value.
                using type = void;
            };

            /// @cond SKIP_DOC
            template<typename... TTypes>
            struct tuple_as_aligned_union<std::tuple<TTypes...>> {
                using type = typename aligned_union<TTypes...>::type;
            };
            /// @endcond

            /// @brief Alias to @ref tuple_as_aligned_union::type
            template<typename TTuple>
            using tuple_as_aligned_union_type = typename tuple_as_aligned_union<TTuple>::type;

            //----------------------------------------

            /// @brief Check whether tuple is unique, i.e. doesn't have contain types.
            template<typename TTuple>
            struct tuple_is_unique {
                static_assert(nil::detail::is_tuple<TTuple>::value, "TTuple must be std::tuple");

                /// @brief Value is set to true when tuple is discovered to be unique.
                static const bool value = false;
            };

            /// @cond SKIP_DOC
            template<typename TFirst, typename... TRest>
            struct tuple_is_unique<std::tuple<TFirst, TRest...>> {
                static const bool value = (!nil::detail::is_in_tuple<TFirst, std::tuple<TRest...>>::value)
                                          && tuple_is_unique<std::tuple<TRest...>>::value;
            };

            template<>
            struct tuple_is_unique<std::tuple<>> {
                static const bool value = true;
            };

            /// @endcond

            //----------------------------------------

            namespace detail {

                template<std::size_t TRem, std::size_t TOff = 0>
                class tuple_for_each_helper {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                        static const std::size_t OffsetedRem = TRem + TOff;
                        static_assert(OffsetedRem <= TupleSize, "Incorrect parameters");

                        static const std::size_t Idx = TupleSize - OffsetedRem;
                        func(std::get<Idx>(std::forward<TTuple>(tuple)));
                        tuple_for_each_helper<TRem - 1, TOff>::exec(std::forward<TTuple>(tuple),
                                                                    std::forward<TFunc>(func));
                    }
                };

                template<std::size_t TOff>
                class tuple_for_each_helper<0, TOff> {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        static_cast<void>(tuple);
                        static_cast<void>(func);
                    }
                };

            }    // namespace detail

            /// @brief Invoke provided functor for every element in the tuple.
            /// @details The functor object class must define operator() with following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TTupleElem>
            ///         void operator()(TTupleElem&& elem) {...}
            ///     };
            ///     @endcode
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.
            template<typename TTuple, typename TFunc>
            void tuple_for_each(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;

                detail::tuple_for_each_helper<TupleSize>::exec(std::forward<TTuple>(tuple), std::forward<TFunc>(func));
            }

            /// @brief Invoke provided functor for every element in the tuple until
            ///     element with specified index is reached.
            /// @details Very similar to tuple_for_each() function, but also receives
            ///     index of the last element as a template parameter. The provided functor
            ///     is NOT invoked for the element with index TIdx.
            /// @tparam TIdx Index of the last (not included) element.
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.
            /// @pre TIdx mustn't exceed number of elements in the tuple.
            template<std::size_t TIdx, typename TTuple, typename TFunc>
            void tuple_for_each_until(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                static_assert(TIdx <= TupleSize, "The index is too big.");

                detail::tuple_for_each_helper<TIdx, TupleSize - TIdx>::exec(std::forward<TTuple>(tuple),
                                                                            std::forward<TFunc>(func));
            }

            /// @brief Invoke provided functor for every element in the tuple starting from
            ///     element with specified index.
            /// @details Very similar to tuple_for_each() function, but also receives
            ///     index of the first element as a template parameter.
            /// @tparam TIdx Index of the first element to invoke functor on.
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.
            /// @pre TIdx must be less than number of elements in the tuple.
            template<std::size_t TIdx, typename TTuple, typename TFunc>
            void tuple_for_each_from(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                static_assert(TIdx <= TupleSize, "The index is too big.");

                detail::tuple_for_each_helper<TupleSize - TIdx>::exec(std::forward<TTuple>(tuple),
                                                                      std::forward<TFunc>(func));
            }

            /// @brief Invoke provided functor for every element in the tuple which indices
            ///     are in range [TFromIdx, TUntilIdx).
            /// @details Very similar to tuple_for_each() function, but also receives
            ///     indices of the first and last elements as a template parameters.
            /// @tparam TFromIdx Index of the first element to invoke functor on.
            /// @tparam TUntilIdx Index of the last (not included) element.
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.
            /// @pre TFromIdx must be less than number of elements in the tuple.
            /// @pre TUntilIdx mustn't exceed number of elements in the tuple.
            /// @pre TFormIdx <= TUntilIdx
            template<std::size_t TFromIdx, std::size_t TUntilIdx, typename TTuple, typename TFunc>
            void tuple_for_each_from_until(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                static_assert(TFromIdx <= TupleSize, "The from index is too big.");

                static_assert(TUntilIdx <= TupleSize, "The until index is too big.");

                static_assert(TFromIdx <= TUntilIdx, "The from index must be less than until index.");

                static const std::size_t FieldsCount = TUntilIdx - TFromIdx;

                detail::tuple_for_each_helper<FieldsCount, TupleSize - TUntilIdx>::exec(std::forward<TTuple>(tuple),
                                                                                        std::forward<TFunc>(func));
            }
            //----------------------------------------

            namespace detail {

                template<std::size_t TRem>
                class tuple_for_each_type_helper {
                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                        static_assert(TRem <= TupleSize, "Incorrect TRem");

                        static const std::size_t Idx = TupleSize - TRem;
                        using ElemType = typename std::tuple_element<Idx, Tuple>::type;
#ifdef _MSC_VER
                        // VS compiler
                        func.operator()<ElemType>();
#else     // #ifdef _MSC_VER
                        func.template operator()<ElemType>();
#endif    // #ifdef _MSC_VER
                        tuple_for_each_type_helper<TRem - 1>::template exec<TTuple>(std::forward<TFunc>(func));
                    }
                };

                template<>
                class tuple_for_each_type_helper<0> {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TFunc &&func) {
                        static_cast<void>(func);
                    }
                };

            }    // namespace detail

            /// @brief Invoke provided functor for every type in the tuple.
            /// @details The functor object class must define operator() with following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TTupleElem>
            ///         void operator()() {...}
            ///     };
            ///     @endcode
            /// @param[in] func Functor object.
            template<typename TTuple, typename TFunc>
            void tuple_for_each_type(TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;

                detail::tuple_for_each_type_helper<TupleSize>::template exec<Tuple>(std::forward<TFunc>(func));
            }
            //----------------------------------------

            namespace detail {

                template<std::size_t TRem>
                class tuple_for_each_with_idx_helper {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                        static_assert(TRem <= TupleSize, "Incorrect TRem");

                        static const std::size_t Idx = TupleSize - TRem;
                        func(std::get<Idx>(std::forward<TTuple>(tuple)), Idx);
                        tuple_for_each_with_idx_helper<TRem - 1>::exec(std::forward<TTuple>(tuple),
                                                                       std::forward<TFunc>(func));
                    }
                };

                template<>
                class tuple_for_each_with_idx_helper<0> {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        static_cast<void>(tuple);
                        static_cast<void>(func);
                    }
                };

            }    // namespace detail

            /// @brief Invoke provided functor for every element in the tuple while providing
            ///     information about element index in the tuple.
            /// @details Very similar to tuple_for_each(), but the operator() in the functor
            ///     receives additional information about index of the element.
            ///     The functor object class must define operator() with following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TTupleElem>
            ///         void operator()(TTupleElem&& elem, std::size_t idx) {...}
            ///     };
            ///     @endcode
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.
            template<typename TTuple, typename TFunc>
            void tuple_for_each_with_idx(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;

                detail::tuple_for_each_with_idx_helper<TupleSize>::exec(std::forward<TTuple>(tuple),
                                                                        std::forward<TFunc>(func));
            }

            namespace detail {

                template<std::size_t TRem>
                class tuple_for_each_with_template_param_idx_helper {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                        static_assert(TRem <= TupleSize, "Incorrect TRem");

                        static const std::size_t Idx = TupleSize - TRem;
#ifdef _MSC_VER
                        // VS compiler
                        func.operator()<Idx>(std::get<Idx>(std::forward<TTuple>(tuple)));
#else     // #ifdef _MSC_VER
                        func.template operator()<Idx>(std::get<Idx>(std::forward<TTuple>(tuple)));
#endif    // #ifdef _MSC_VER
                        tuple_for_each_with_template_param_idx_helper<TRem - 1>::exec(std::forward<TTuple>(tuple),
                                                                                      std::forward<TFunc>(func));
                    }
                };

                template<>
                class tuple_for_each_with_template_param_idx_helper<0> {

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(TTuple &&tuple, TFunc &&func) {
                        static_cast<void>(tuple);
                        static_cast<void>(func);
                    }
                };

            }    // namespace detail

            /// @brief Invoke provided functor for every element in the tuple while providing
            ///     information about element index in the tuple as a template parameter.
            /// @details Very similar to tuple_for_each_with_idx(), but the operator() in the functor
            ///     receives additional information about index of the element as a template
            ///     parameter instead of as argument to the function.
            ///     The functor object class must define operator() with following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <std::size_t TIdx, typename TTupleElem>
            ///         void operator()(TTupleElem&& elem) {...}
            ///     };
            ///     @endcode
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] func Functor object.

            template<typename TTuple, typename TFunc>
            void tuple_for_each_with_template_param_idx(TTuple &&tuple, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;

                detail::tuple_for_each_with_template_param_idx_helper<TupleSize>::exec(std::forward<TTuple>(tuple),
                                                                                       std::forward<TFunc>(func));
            }

            //----------------------------------------

            namespace detail {

                template<std::size_t TOff, std::size_t TRem>
                class tuple_accumulate_helper {

                public:
                    template<typename TTuple, typename TValue, typename TFunc>
                    static constexpr TValue exec(TTuple &&tuple, const TValue &value, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static_assert((TOff + TRem) <= std::tuple_size<Tuple>::value, "Incorrect params");

                        return tuple_accumulate_helper<TOff + 1, TRem - 1>::exec(
                            std::forward<TTuple>(tuple), func(value, std::get<TOff>(std::forward<TTuple>(tuple))),
                            std::forward<TFunc>(func));
                    }
                };

                template<std::size_t TOff>
                class tuple_accumulate_helper<TOff, 0> {
                public:
                    template<typename TTuple, typename TValue, typename TFunc>
                    static constexpr TValue exec(TTuple && /* tuple */, const TValue &value, TFunc && /* func */) {
                        return value;
                    }
                };

            }    // namespace detail

            /// @brief Performs "accumulate" algorithm on every element of the tuple.
            /// @details The algorithm invokes operator() of the provided functor object
            ///     with initial value and first element of the tuple, then provides the
            ///     returned value as a parameter to the next invocation of operator() and
            ///     second element in the tuple, and so on until all elements in the tuple
            ///     is handled.
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] value Initial value.
            /// @param[in] func Functor object. The class must provide operator() with the
            ///     following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TValue, typename TTupleElem>
            ///         TValue operator()(const TValue& value, TTupleElem&& elem) {...}
            ///     };
            ///     @endcode
            /// @return Returns the result of the last invocation of the functor's operator().
            template<typename TTuple, typename TValue, typename TFunc>
            constexpr TValue tuple_accumulate(TTuple &&tuple, const TValue &value, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;

                return detail::tuple_accumulate_helper<0, std::tuple_size<Tuple>::value>::exec(
                    std::forward<TTuple>(tuple), value, std::forward<TFunc>(func));
            }

            /// @brief Performs "accumulate" algorithm on every element of the tuple.
            /// @details Similar to @ref tuple_accumulate(), but allows specifying range of
            ///     indices of tuple elements.
            /// @tparam TFrom Index of the first tuple element to evaluate
            /// @tparam TUntil Index of the one past the last tuple element to evaluate.
            /// @param[in] tuple Reference (l- or r-value) to tuple object.
            /// @param[in] value Initial value.
            /// @param[in] func Functor object. The class must provide operator() with the
            ///     following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TValue, typename TTupleElem>
            ///         TValue operator()(const TValue& value, TTupleElem&& elem) {...}
            ///     };
            ///     @endcode
            /// @return Returns the result of the last invocation of the functor's operator().
            template<std::size_t TFrom, std::size_t TUntil, typename TTuple, typename TValue, typename TFunc>
            constexpr TValue tuple_accumulate_from_until(TTuple &&tuple, const TValue &value, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;

                static_assert(TFrom <= TUntil, "TFrom mustn't be greater that TUntil");
                static_assert(TUntil <= std::tuple_size<Tuple>::value, "TUntil mustn't exceed size of the tuple");

                return detail::tuple_accumulate_helper<TFrom, TUntil - TFrom>::exec(std::forward<TTuple>(tuple), value,
                                                                                    std::forward<TFunc>(func));
            }

            //----------------------------------------

            namespace detail {

                template<std::size_t TOff, std::size_t TRem>
                class tuple_type_accumulate_helper {

                public:
                    template<typename TTuple, typename TValue, typename TFunc>
                    static constexpr TValue exec(const TValue &value, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static_assert((TOff + TRem) <= std::tuple_size<Tuple>::value, "Incorrect TRem");

                        return tuple_type_accumulate_helper<TOff + 1, TRem - 1>::template exec<Tuple>(
#ifdef _MSC_VER
                            func.operator()
#else
                            func.template operator()
#endif
                            <typename std::tuple_element<TOff, Tuple>::type>(value),
                            std::forward<TFunc>(func));
                    }
                };

                template<std::size_t TOff>
                class tuple_type_accumulate_helper<TOff, 0> {

                public:
                    template<typename TTuple, typename TValue, typename TFunc>
                    static constexpr TValue exec(const TValue &value, TFunc && /* func */) {
                        return value;
                    }
                };

            }    // namespace detail

            /// @brief Performs "accumulate" algorithm on every type of the tuple.
            /// @details Very similar to tuple_accumulate(), but without actual tuple object,
            ///     provides only type information to operator() of the functor.
            /// @param[in] value Initial value.
            /// @param[in] func Functor object. The class must provide operator() with the
            ///     following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TTupleElem, typename TValue>
            ///         TValue operator()(const TValue& value) {...}
            ///     };
            ///     @endcode
            /// @return Returns the result of the last invocation of the functor's operator().
            template<typename TTuple, typename TValue, typename TFunc>
            constexpr TValue tuple_type_accumulate(const TValue &value, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                return detail::tuple_type_accumulate_helper<0, std::tuple_size<Tuple>::value>::template exec<Tuple>(
                    value, std::forward<TFunc>(func));
            }

            /// @brief Performs "accumulate" algorithm on specified types inside the tuple.
            /// @details Very similar to @ref tuple_type_accumulate(), but allows specifying range of
            ///     indices of tuple elements.
            /// @tparam TFrom Index of the first tuple type to evaluate
            /// @tparam TUntil Index of the one past the last tuple type to evaluate.
            /// @param[in] value Initial value.
            /// @param[in] func Functor object. The class must provide operator() with the
            ///     following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         template <typename TTupleElem, typename TValue>
            ///         TValue operator()(const TValue& value) {...}
            ///     };
            ///     @endcode
            /// @return Returns the result of the last invocation of the functor's operator().
            template<std::size_t TFrom, std::size_t TUntil, typename TTuple, typename TValue, typename TFunc>
            constexpr TValue tuple_type_accumulate_from_until(const TValue &value, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static_assert(TFrom <= TUntil, "TFrom mustn't be greater that TUntil");
                static_assert(TUntil <= std::tuple_size<Tuple>::value, "TUntil mustn't exceed size of the tuple");
                return detail::tuple_type_accumulate_helper<TFrom, TUntil - TFrom>::template exec<Tuple>(
                    value, std::forward<TFunc>(func));
            }

            //----------------------------------------

            /// @brief Provides the type of <a
            /// href="http://en.cppreference.com/w/cpp/utility/tuple/tuple_cat">std::tuple_cat</a> operation.
            /// @tparam TFirst Type of first tuple
            /// @tparam TSecond Type of the second tuple.
            template<typename TFirst, typename TSecond>
            struct tuple_cat {
                static_assert(nil::detail::is_tuple<TFirst>::value, "TFirst must be tuple");
                static_assert(nil::detail::is_tuple<TSecond>::value, "TSecond must be tuple");

                /// @brief Result type of tuples concatenation.
                using type = typename std::decay<decltype(std::tuple_cat(std::declval<TFirst>(),
                                                                         std::declval<TSecond>()))>::type;
            };

            /// @brief Alias to typename TupleCat<TField, TTuple>::type
            /// @related TupleCat
            template<typename TField, typename TTuple>
            using tuple_cat_type = typename tuple_cat<TField, TTuple>::type;

            //----------------------------------------

            namespace detail {

                template<std::size_t TFromIdx, std::size_t TToIdx, std::size_t TCount>
                class tuple_selected_type_helper {
                    static_assert(TCount == (TToIdx - TFromIdx), "Internal error: Bad parameters");
                    static_assert(TFromIdx < TToIdx, "Internal error: Bad parameters");

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(std::size_t idx, TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                        static_assert(TCount <= TupleSize, "Incorrect TCount");
                        static_assert(0U < TCount, "Incorrect instantiation");

                        MARSHALLING_ASSERT(TFromIdx <= idx);
                        MARSHALLING_ASSERT(idx < TToIdx);
                        if (idx == TFromIdx) {
                            tuple_selected_type_helper<TFromIdx, TFromIdx + 1, 1U>::template exec<TTuple>(
                                idx, std::forward<TFunc>(func));
                            return;
                        }

                        static const std::size_t MidIdx = TFromIdx + TCount / 2;
                        static_assert(MidIdx < TToIdx, "Internal error: bad calculation");
                        static_assert(TFromIdx <= MidIdx, "Internal error: bad calculation");
                        if (MidIdx <= idx) {
                            tuple_selected_type_helper<MidIdx, TToIdx, TToIdx - MidIdx>::template exec<TTuple>(
                                idx, std::forward<TFunc>(func));
                            return;
                        }

                        tuple_selected_type_helper<TFromIdx, MidIdx, MidIdx - TFromIdx>::template exec<TTuple>(
                            idx, std::forward<TFunc>(func));
                    }
                };

                template<std::size_t TFromIdx, std::size_t TToIdx>
                class tuple_selected_type_helper<TFromIdx, TToIdx, 1U> {
                    static_assert((TFromIdx + 1) == TToIdx, "Internal error: Bad parameters");

                public:
                    template<typename TTuple, typename TFunc>
                    static void exec(std::size_t idx, TFunc &&func) {
                        static_cast<void>(idx);
                        MARSHALLING_ASSERT(idx == TFromIdx);
                        using ElemType = typename std::tuple_element<TFromIdx, TTuple>::type;
#ifdef _MSC_VER
                        // VS compiler
                        func.operator()<TFromIdx, ElemType>();
#else     // #ifdef _MSC_VER
                        func.template operator()<TFromIdx, ElemType>();
#endif    // #ifdef _MSC_VER
                    }
                };

            }    // namespace detail

            /// @brief Invoke provided functor for a selected type when element index
            ///     is known only at run time.
            /// @details The functor object class must define operator() with following signature:
            ///     @code
            ///     struct MyFunc
            ///     {
            ///         // TIdx - index of the type inside the tuple
            ///         // TTupleElem - type inside the tuple
            ///         template <std::size_t TIdx, typename TTupleElem>
            ///         void operator()() {...}
            ///     };
            ///     @endcode
            /// @param[in] idx Index of the type in the tuple
            /// @param[in] func Functor object.
            template<typename TTuple, typename TFunc>
            void tuple_for_selected_type(std::size_t idx, TFunc &&func) {
                using Tuple = typename std::decay<TTuple>::type;
                static_assert(nil::detail::is_tuple<Tuple>::value, "Provided tupe must be std::tuple");
                static const std::size_t TupleSize = std::tuple_size<Tuple>::value;
                static_assert(0U < TupleSize, "Empty tuples are not supported");

                detail::tuple_selected_type_helper<0, TupleSize, TupleSize>::template exec<Tuple>(
                    idx, std::forward<TFunc>(func));
            }
            //----------------------------------------

            namespace detail {

                template<typename TTuple>
                struct tuple_strip_first;

                template<typename TFirst, typename... TRest>
                struct tuple_strip_first<std::tuple<TFirst, TRest...>> {
                    using type = std::tuple<TRest...>;
                };

                template<typename TTuple>
                using tuple_strip_first_type = typename tuple_strip_first<TTuple>::type;

                template<typename TTail, typename TTuple, std::size_t TStripRem>
                struct tuple_tail_check_helpler {
                    static_assert(0U < TStripRem, "Invalid instantiation");
                    static const bool value
                        = tuple_tail_check_helpler<TTail, tuple_strip_first_type<TTuple>, TStripRem - 1>::value;
                };

                template<typename TTail, typename TTuple>
                struct tuple_tail_check_helpler<TTail, TTuple, 0> {
                    static const bool value = std::is_same<TTail, TTuple>::value;
                };

            }    // namespace detail

            /// @brief Compile time check of whether one tuple is a "tail" of another.
            /// @tparam TTail Tail tuple
            /// @tparam TTuple Containing tuple
            template<typename TTail, typename TTuple>
            constexpr bool tuple_is_tail_of() {
                static_assert(nil::detail::is_tuple<TTail>::value, "TTail param must be tuple");
                static_assert(nil::detail::is_tuple<TTuple>::value, "TTuple param must be tuple");
                return std::tuple_size<TTail>::value <= std::tuple_size<TTuple>::value
                       && detail::tuple_tail_check_helpler<
                           TTail, TTuple, std::tuple_size<TTuple>::value - std::tuple_size<TTail>::value>::value;
                //    return true;
            }

            //----------------------------------------

            namespace detail {

                template<std::size_t TRem>
                class tuple_type_is_any_of_helper {
                public:
                    template<typename TTuple, typename TFunc>
                    static constexpr bool check(TFunc &&func) {
                        using Tuple = typename std::decay<TTuple>::type;
                        static_assert(nil::detail::is_tuple<Tuple>::value, "TTuple must be std::tuple");
                        static_assert(TRem <= std::tuple_size<Tuple>::value, "Incorrect TRem");
                        using ElemType = typename std::tuple_element<std::tuple_size<Tuple>::value - TRem, Tuple>::type;
                        return
#ifdef _MSC_VER
                            // VS compiler
                            func.operator()<ElemType>() ||
#else     // #ifdef _MSC_VER
                            func.template operator()<ElemType>() ||
#endif    // #ifdef _MSC_VER
                            tuple_type_is_any_of_helper<TRem - 1>::template check<TTuple>(std::forward<TFunc>(func));
                    }
                };

                template<>
                class tuple_type_is_any_of_helper<0> {

                public:
                    template<typename TTuple, typename TFunc>
                    static constexpr bool check(TFunc &&) {
                        return false;
                    }
                };

            }    // namespace detail

            template<typename TTuple, typename TFunc>
            constexpr bool tuple_type_is_any_of(TFunc &&func) {
                static_assert(nil::detail::is_tuple<TTuple>::value, "Tuple as argument is expected");
                return detail::tuple_type_is_any_of_helper<std::tuple_size<TTuple>::value>::template check<TTuple>(
                    std::forward<TFunc>(func));
            }

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_PROCESSING_TUPLE_HPP
