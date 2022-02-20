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

#ifndef CRYPTO3_PUBKEY_TYPE_TRAITS_HPP
#define CRYPTO3_PUBKEY_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            using namespace boost::mpl::placeholders;

            BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_DATA(has_eddsa_context, context)
            template<typename T>
            struct is_eddsa_params {
                static constexpr bool value = has_eddsa_context<T, const typename T::context_type>::value;
                typedef T type;
            };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct bls;

            template<typename T>
            struct is_bls : std::bool_constant<false> { };

            template<typename PublicParams, template<typename, typename> class BlsVersion,
                     template<typename> class BlsScheme, typename CurveType>
            struct is_bls<bls<PublicParams, BlsVersion, BlsScheme, CurveType>> : std::bool_constant<true> { };

            template<typename Group>
            struct shamir_sss;

            template<typename Group>
            struct feldman_sss;

            template<typename Group>
            struct pedersen_dkg;

            template<typename Group>
            struct weighted_shamir_sss;

            template<typename T>
            struct is_shamir_sss : std::bool_constant<false> { };

            template<typename Group>
            struct is_shamir_sss<shamir_sss<Group>> : std::bool_constant<true> { };

            template<typename T>
            struct is_feldman_sss : std::bool_constant<false> { };

            template<typename Group>
            struct is_feldman_sss<feldman_sss<Group>> : std::bool_constant<true> { };

            template<typename T>
            struct is_pedersen_dkg : std::bool_constant<false> { };

            template<typename Group>
            struct is_pedersen_dkg<pedersen_dkg<Group>> : std::bool_constant<true> { };

            template<typename T>
            struct is_weighted_shamir_sss : std::bool_constant<false> { };

            template<typename Group>
            struct is_weighted_shamir_sss<weighted_shamir_sss<Group>> : std::bool_constant<true> { };

        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_TYPE_TRAITS_HPP
