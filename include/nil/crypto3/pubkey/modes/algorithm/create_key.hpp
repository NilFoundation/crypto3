//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_MODES_CREATE_KEY_HPP
#define CRYPTO3_PUBKEY_MODES_CREATE_KEY_HPP

#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/pubkey/secret_sharing.hpp>
#include <nil/crypto3/pubkey/dkg.hpp>

#include <nil/crypto3/pubkey/private_key.hpp>

namespace nil {
    namespace crypto3 {
        template<typename Scheme,
                 typename InputIterator,
                 typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::shamir_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(InputIterator first, InputIterator last, Number n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

            using privkeys_type = std::vector<pubkey::private_key<Scheme>>;
            using sss_no_key_ops_type = typename pubkey::private_key<Scheme>::sss_public_key_no_key_ops_type;

            typename sss_no_key_ops_type::shares_type shares =
                nil::crypto3::deal_shares<SecretSharingScheme>(first, last, n);
            privkeys_type privkeys;
            for (const auto &s : shares) {
                privkeys.emplace_back(s);
            }
            auto PK = pubkey::public_key<Scheme>(sss_no_key_ops_type::get_public_coeffs(first, last).front());
            return std::make_pair(PK, privkeys);
        }

        template<typename Scheme,
                 typename SinglePassRange,
                 typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::shamir_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const SinglePassRange &r, Number n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            return create_key<Scheme>(r.begin(), r.end(), n);
        }

        template<typename Scheme,
                 typename InputIterator1,
                 typename InputIterator2,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<InputIterator1>::value_type,
                 typename ValueType2 = typename std::iterator_traits<InputIterator2>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_weight_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::weighted_shamir_sss<typename SecretSharingScheme::group_type>,
                         SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator1>));
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator2>));

            using privkeys_type = std::vector<pubkey::private_key<Scheme>>;
            using sss_no_key_ops_type = typename pubkey::private_key<Scheme>::sss_public_key_no_key_ops_type;

            typename sss_no_key_ops_type::shares_type shares = nil::crypto3::deal_shares<SecretSharingScheme>(
                first1, last1, first2, last2, std::distance(first2, last2));
            privkeys_type privkeys;
            for (const auto &s : shares) {
                privkeys.emplace_back(s, std::distance(first1, last1));
            }
            auto PK = pubkey::public_key<Scheme>(sss_no_key_ops_type::get_public_coeffs(first1, last1).front(),
                                                 std::distance(first2, last2));
            return std::make_pair(PK, privkeys);
        }

        template<typename Scheme,
                 typename SinglePassRange,
                 typename Weights,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                 typename ValueType2 = typename std::iterator_traits<typename Weights::iterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_weight_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::weighted_shamir_sss<typename SecretSharingScheme::group_type>,
                         SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const SinglePassRange &r, const Weights &weights) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Weights>));
            return create_key<Scheme>(r.begin(), r.end(), weights.begin(), weights.end());
        }

        //        template<typename Key, typename Shares>
        //        inline typename std::enable_if<
        //            std::is_same<pedersen_dkg<typename Key::base_scheme_public_key_type::public_key_type::group_type>,
        //                         typename Key::sss_public_key_group_type>::type,
        //            Key>
        //            create_key() {
        //            using result_type = Key;
        //        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard