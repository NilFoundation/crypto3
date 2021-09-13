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

#ifndef CRYPTO3_PK_PAD_TYPE_TRAITS_HPP
#define CRYPTO3_PK_PAD_TYPE_TRAITS_HPP

#include <type_traits>

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                using namespace boost::mpl::placeholders;

                BOOST_TTI_HAS_TYPE(encoding_policy_type)
                BOOST_TTI_HAS_TYPE(verification_policy_type)
                BOOST_TTI_HAS_TYPE(decoding_policy_type)
                BOOST_TTI_HAS_TYPE(recovering_policy_type)

                BOOST_TTI_HAS_STATIC_MEMBER_DATA(dst)

                template<typename T>
                struct is_emsa_policy : std::bool_constant<has_type_encoding_policy_type<T>::value &&
                                                           has_type_verification_policy_type<T>::value> {
                    typedef T type;
                };

                template<typename T>
                struct is_eme_policy : std::bool_constant<has_type_encoding_policy_type<T>::value &&
                                                          has_type_decoding_policy_type<T>::value> {
                    typedef T type;
                };

                template<typename T>
                struct is_emsr_policy : std::bool_constant<has_type_encoding_policy_type<T>::value &&
                                                           has_type_recovering_policy_type<T>::value> {
                    typedef T type;
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PK_PAD_TYPE_TRAITS_HPP
