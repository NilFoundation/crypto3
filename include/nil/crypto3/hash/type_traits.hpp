//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_HASH_TYPE_TRAITS_HPP
#define CRYPTO3_HASH_TYPE_TRAITS_HPP

#include <boost/config.hpp>

#ifdef __has_include
#if __has_include(<version>)
#include <version>
#ifdef __cpp_lib_is_constant_evaluated
#include <type_traits>
#define CRYPTO3_HAS_IS_CONSTANT_EVALUATED
#endif
#endif
#endif

#ifdef __has_builtin
#if __has_builtin(__builtin_is_constant_evaluated) && !defined(BOOST_NO_CXX14_CONSTEXPR) && \
    !defined(BOOST_NO_CXX11_UNIFIED_INITIALIZATION_SYNTAX)
#define CRYPTO3_HAS_BUILTIN_IS_CONSTANT_EVALUATED
#endif
#endif
//
// MSVC also supports __builtin_is_constant_evaluated if it's recent enough:
//
#if defined(_MSC_FULL_VER) && (_MSC_FULL_VER >= 192528326)
#define CRYPTO3_HAS_BUILTIN_IS_CONSTANT_EVALUATED
#endif
//
// As does GCC-9:
//
#if defined(BOOST_GCC) && !defined(BOOST_NO_CXX14_CONSTEXPR) && (__GNUC__ >= 9) && \
    !defined(CRYPTO3_HAS_BUILTIN_IS_CONSTANT_EVALUATED)
#define CRYPTO3_HAS_BUILTIN_IS_CONSTANT_EVALUATED
#endif

#if defined(CRYPTO3_HAS_IS_CONSTANT_EVALUATED) && !defined(BOOST_NO_CXX14_CONSTEXPR)
#define CRYPTO3_IS_CONST_EVALUATED(x) std::is_constant_evaluated()
#elif defined(CRYPTO3_HAS_BUILTIN_IS_CONSTANT_EVALUATED)
#define CRYPTO3_IS_CONST_EVALUATED(x) __builtin_is_constant_evaluated()
#elif !defined(BOOST_NO_CXX14_CONSTEXPR) && defined(BOOST_GCC) && (__GNUC__ >= 6)
#define CRYPTO3_IS_CONST_EVALUATED(x) __builtin_constant_p(x)
#else
#define CRYPTO3_NO_CONSTEXPR_DETECTION
#endif

#define CRYPTO3_CXX14_CONSTEXPR BOOST_CXX14_CONSTEXPR
//
// Early compiler versions trip over the constexpr code:
//
#if defined(__clang__) && (__clang_major__ < 5)
#undef CRYPTO3_CXX14_CONSTEXPR
#define CRYPTO3_CXX14_CONSTEXPR
#endif
#if defined(__apple_build_version__) && (__clang_major__ < 9)
#undef CRYPTO3_CXX14_CONSTEXPR
#define CRYPTO3_CXX14_CONSTEXPR
#endif
#if defined(BOOST_GCC) && (__GNUC__ < 6)
#undef CRYPTO3_CXX14_CONSTEXPR
#define CRYPTO3_CXX14_CONSTEXPR
#endif
#if defined(BOOST_INTEL)
#undef CRYPTO3_CXX14_CONSTEXPR
#define CRYPTO3_CXX14_CONSTEXPR
#define CRYPTO3_NO_CONSTEXPR_DETECTION
#endif

#ifdef CRYPTO3_NO_CONSTEXPR_DETECTION
#define BOOST_CXX14_CONSTEXPR_IF_DETECTION
#else
#define BOOST_CXX14_CONSTEXPR_IF_DETECTION constexpr
#endif

#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            template<typename PolicyType>
            struct poseidon;

            template<typename Params, typename Hash, typename Group>
            struct find_group_hash;

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen_to_point;

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen;

            template<typename Field, typename Hash, typename Params>
            struct h2f;

            template<typename Group, typename Hash, typename Params>
            struct h2c;

            template<typename Hash>
            struct is_find_group_hash : std::integral_constant<bool, false> { };

            template<typename Params, typename Hash, typename Group>
            struct is_find_group_hash<find_group_hash<Params, Hash, Group>> : std::integral_constant<bool, true> { };

            template<typename Hash>
            struct is_pedersen : std::integral_constant<bool, false> { };

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct is_pedersen<pedersen_to_point<Params, BasePointGeneratorHash, Group>>
                : std::integral_constant<bool, true> { };

            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct is_pedersen<pedersen<Params, BasePointGeneratorHash, Group>> : std::integral_constant<bool, true> {
            };

            template<typename Hash>
            struct is_h2f : std::integral_constant<bool, false> { };

            template<typename Field, typename Hash, typename Params>
            struct is_h2f<h2f<Field, Hash, Params>> : std::integral_constant<bool, true> { };

            template<typename Hash>
            struct is_h2c : std::integral_constant<bool, false> { };

            template<typename Group, typename Hash, typename Params>
            struct is_h2c<h2c<Group, Hash, Params>> : std::integral_constant<bool, true> { };

            // TODO: change this to more generic type trait to check for all sponge based hashes.
            template<typename HashType, typename Enable = void>
            struct is_poseidon {
            public:
                static const bool value = false;
            };

            template<typename HashType>
            struct is_poseidon<HashType, typename std::enable_if_t<std::is_same<nil::crypto3::hashes::poseidon<typename HashType::policy_type>, HashType>::value>> {
            public:
                static const bool value = true;
                typedef HashType type;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_TYPE_TRAITS_HPP
