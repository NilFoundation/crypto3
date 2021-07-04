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

/// @file nil/marshalling/assert_type.hpp
/// This file contains classes required for generic custom assertion
/// functionality

#ifndef MARSHALLING_ASSERT_TYPE_HPP
#define MARSHALLING_ASSERT_TYPE_HPP

#include <cassert>
#include <type_traits>
#include <utility>

namespace nil {
    namespace marshalling {

        /// @brief Base class for any custom assertion behaviour.
        /// @details In order to implement custom assertion failure behaviour it
        ///          is necessary to inherit from this class and override
        ///          fail() virtual member function.
        /// @headerfile nil/marshalling/assert_type.hpp
        class assert_type {
        public:
            /// @brief Destructor
            virtual ~assert_type() noexcept {
            }

            /// @brief Pure virtual function to be called when assertion fails.
            /// @param[in] expr Assertion condition/expression
            /// @param[in] file File name
            /// @param[in] line Line number of the assert statement.
            /// @param[in] function Function name.
            virtual void fail(const char *expr, const char *file, unsigned int line, const char *function) = 0;

        private:
        };

        /// @cond DOCUMENT_ASSERT_MANAGER
        class assert_manager {
        public:
            static assert_manager &instance() {
                static assert_manager mgr;
                return mgr;
            }

            assert_manager(const assert_manager &) = delete;

            assert_manager &operator=(const assert_manager &) = delete;

            assert_type *reset(assert_type *newAssert = nullptr) {
                auto prevAssert = assert_;
                assert_ = newAssert;
                return prevAssert;
            }

            assert_type *get_assert() {
                return assert_;
            }

            bool has_assert_registered() const {
                return (assert_ != nullptr);
            }

            static void infinite_loop() {
                while (true) {
                };
            }

        private:
            assert_manager() : assert_(nullptr) {
            }

            assert_type *assert_;
        };

        /// @endcond

        /// @brief Enable new assertion behaviour.
        /// @details Instantiate object of this class to enable new behaviour of
        ///          assertion failure.
        /// @tparam TAssert Class derived from Assert that implements new custom
        ///                 behaviour of the assertion failure.
        /// @pre TAssert class must be derived from nil::marshalling::assert_type.
        /// @headerfile nil/marshalling/assert_type.hpp
        template<typename TAssert>
        class enable_assert {
            static_assert(std::is_base_of<assert_type, TAssert>::value,
                          "TAssert class must be derived class of assert_type");

        public:
            /// Type of assert object.
            using AssertType = TAssert;

            /// @brief Constructor
            /// @details Registers new assertion failure behaviour. It forwards
            ///          all the provided parameters to the constructor of embedded
            ///          assertion object of type TAssert.
            /// @param args Arguments to pass to the assertion class constructor.
            template<typename... TParams>
            enable_assert(TParams &&...args) :
                assert_(std::forward<TParams>(args)...), prevAssert_(assert_manager::instance().reset(&assert_)) {
            }

            /// @brief Destructor
            /// @details Restores the assertion behaviour that was recorded during
            ///          the instantiation of this object.
            ~enable_assert() noexcept {
                assert_manager::instance().reset(prevAssert_);
            }

            /// @brief Provides reference to internal Assert object
            /// @return Reference to object of type TAssert.
            AssertType &get_assert() {
                return assert_;
            }

        private:
            AssertType assert_;
            assert_type *prevAssert_;
        };

#ifndef NDEBUG

/// @cond DOCUCMENT_AM_ASSERT_FUNCTION
#ifndef __ASSERT_FUNCTION
#define MARSHALLING_ASSERT_FUNCTION_STR __FUNCTION__
#else    // #ifndef __ASSERT_FUNCTION
#define MARSHALLING_ASSERT_FUNCTION_STR __ASSERT_FUNCTION
#endif    // #ifndef __ASSERT_FUNCTION

#ifndef NOSTDLIB
#define MARSHALLING_ASSERT_FAIL_FUNC(expr) assert(expr)
#else    // #ifndef NOSTDLIB
#define MARSHALLING_ASSERT_FAIL_FUNC(expr) nil::marshalling::assert_manager::instance().infinite_loop()
#endif    // #ifndef NOSTDLIB

/// @endcond

/// @brief Generic assert macro
/// @details Will use custom assertion failure behaviour if such is defined,
///          otherwise it will use standard "assert()" macro.
///          In case NOSTDLIB is defined and no custom assertion failure was
///          enabled, infinite loop will be executed.
/// @param expr Boolean expression
#define MARSHALLING_ASSERT(expr)                                                      \
    ((expr) ? static_cast<void>(0) :                                                  \
              (nil::marshalling::assert_manager::instance().has_assert_registered() ? \
                   nil::marshalling::assert_manager::instance().get_assert()->fail(   \
                       #expr, __FILE__, __LINE__, MARSHALLING_ASSERT_FUNCTION_STR) :  \
                   MARSHALLING_ASSERT_FAIL_FUNC(expr)))

#else    // #ifndef NDEBUG

#define MARSHALLING_ASSERT(expr) static_cast<void>(0)

#endif    // #ifndef NDEBUG

/// @brief Same as @ref MARSHALLING_ASSERT
/// @details Kept for backward compatibility of already written protocols.
#define GASSERT(expr) MARSHALLING_ASSERT(expr)

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_ASSERT_TYPE_HPP
