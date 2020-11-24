//---------------------------------------------------------------------------//
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_SCOPE_GUARD_HPP
#define MARSHALLING_SCOPE_GUARD_HPP

#include <memory>
#include <functional>
#include <type_traits>

namespace nil {
    namespace marshalling {

        namespace util {

            /// @brief Implements <a href="https://en.wikibooks.org/wiki/More_C%2B%2B_Idioms/Scope_Guard">Scope Guard
            /// Idiom</a>.
            /// @details Scope guard idiom allows to call
            ///          any function with any number of parameters when the guard is
            ///          destructed, unless release() method is called prior to the
            ///          destruction. The scope guard doesn't use any dynamic memory
            ///          allocation and takes as much space on the stack as needed
            ///          to bind the provided function with all its arguments.
            ///          The template parameter must be type of the functor
            ///          that doesn't receive any parameters and doesn't return any value.
            ///          In order to properly create such guard use make_scope_guard()
            ///          function. For example:
            ///          @code
            ///          // Binding function with parameters:
            ///          auto guard = nil::marshalling::utilities::make_scope_guard(&func, std::ref(arg1), arg2);
            ///
            ///          // Binding lamda function:
            ///          auto guard =
            ///              nil::marshalling::utilities::make_scope_guard([&argByRef, argByValue]()
            ///                  {
            ///                      ...// Some code here
            ///                  });
            ///          @endcode
            ///          Note that all the bound parameters are passed by value, if
            ///          there is any need to bind function with reference to some
            ///          object, use "std::ref()" or "std::cref()" for const reference.
            ///          Also note that the guard doesn't provide copy constructor and
            ///          assignment operator, it supports only move semantics.
            /// @tparam TFunc Functor object type.
            /// @headerfile nil/marshalling/utilities/ScopeGuard.h
            template<typename TFunc>
            class scope_guard {
            public:
                /// @brief Constructor
                /// @param[in] func Functor that will be executed when the scope guard is
                ///            destructed unless it is "released." Must provide move/copy
                ///            constructor.
                explicit scope_guard(TFunc &&func) : func_(std::forward<TFunc>(func)), engaged_(true) {
                }

                /// @brief No copy is allowed.
                scope_guard(const scope_guard &guard) = delete;

                /// @brief Move constructor
                /// @details After the functor is moved, it will be released in the
                ///          provided guard.
                /// @param[in] guard The other scope guard of the same type.
                scope_guard(scope_guard &&guard) : func_(std::move(guard.func_)), engaged_(std::move(guard.engaged_)) {
                    guard.release();
                }

                /// @brief Destructor
                /// @post The functor is called unless it was released with release()
                ///       prior to destruction.
                ~scope_guard() noexcept {
                    if (!is_released()) {
                        func_();
                    }
                }

                /// @brief No copy is allowed.
                scope_guard &operator=(const scope_guard &guard) = delete;

                /// @brief Release the bound functor.
                /// @post The functor won't be called when the scope guard is out of scope.
                void release() {
                    engaged_ = false;
                }

                /// @brief Check whether the functor is released.
                /// @return true in case of being released.
                bool is_released() const {
                    return !engaged_;
                }

            private:
                typename std::remove_reference<TFunc>::type func_;
                bool engaged_;
            };

            /// @brief Create scope guard with provided functor.
            /// @details Use this function to create a scope guard with lambda function.
            ///          For example:
            ///          @code
            ///          auto guard =
            ///              nil::marshalling::utilities::make_scope_guard([&argByRef, argByValue]()
            ///                  {
            ///                      ...// Some code here
            ///                  });
            ///          @endcode
            /// @tparam TFunctor Functor type, should be deduced automatically based on
            ///         provided argument.
            /// @param[in] func Functor
            /// @return Scope guard.
            /// @related ScopeGuard
            template<typename TFunctor>
            scope_guard<TFunctor> make_scope_guard(TFunctor &&func) {
                return scope_guard<TFunctor>(std::forward<TFunctor>(func));
            }

            /// @brief Create scope guard by binding the provided function and
            ///        all the arguments.
            /// @details Use this function to create a scope guard when some function
            ///          with one or more arguments needs to be called.
            ///          For example:
            ///          @code
            ///          // Binding function with parameters:
            ///          auto guard = nil::marshalling::utilities::make_scope_guard(&func, std::ref(arg1), arg2);
            ///          @endcode
            ///          Note that all the bound parameters are passed by value, if there
            ///          is any need to bind function with reference to some object,
            ///          use "std::ref()" or "std::cref()" for const reference.
            ///          Also note that this function uses variadic template arguments which
            ///          were introduced in C++11. Please make sure that you compiler
            ///          supports it.
            /// @tparam TFunc Pointer to function type.
            /// @tparam TParams Types of other arguments.
            /// @param[in] func Functor
            /// @param[in] args Function arguments
            /// @return Scope guard.
            /// @related ScopeGuard
            template<typename TFunc, typename... TParams>
            auto make_scope_guard(TFunc &&func, TParams... args)
                -> scope_guard<decltype(std::bind(std::forward<TFunc>(func), std::forward<TParams>(args)...))> {
                auto bindObj = std::bind(std::forward<TFunc>(func), std::forward<TParams>(args)...);
                return scope_guard<decltype(bindObj)>(std::move(bindObj));
            }

            // Class implementation part

        }    // namespace util

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_SCOPE_GUARD_HPP
