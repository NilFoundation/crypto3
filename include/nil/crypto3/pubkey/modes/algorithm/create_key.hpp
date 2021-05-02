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

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>
#include <nil/crypto3/pubkey/algorithm/deal_share.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_share.hpp>

namespace nil {
    namespace crypto3 {
        //
        // CoeffsIterator - coefficients of polynomial
        //
        template<typename Scheme, typename CoeffsIterator, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<CoeffsIterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::shamir_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value ||
                std::is_same<pubkey::feldman_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(CoeffsIterator first, CoeffsIterator last, Number n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIterator>));

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

        //
        // CoeffsRange - coefficients of polynomial
        //
        template<typename Scheme, typename CoeffsRange, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<typename CoeffsRange::iterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::shamir_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value ||
                std::is_same<pubkey::feldman_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const CoeffsRange &r, Number n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));
            return create_key<Scheme>(r.begin(), r.end(), n);
        }

        //
        // InputIterator - public representation values of polynomial's coefficients
        //
        template<typename Scheme, typename CoeffsIterator, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<CoeffsIterator>::value_type,
                 typename SecretSharingScheme::template check_public_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::feldman_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            pubkey::private_key<Scheme>>::type
            create_key(CoeffsIterator first,
                       CoeffsIterator last,
                       typename SecretSharingScheme::share_type share,
                       Number n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIterator>));

            using privkey_type = pubkey::private_key<Scheme>;

            assert(static_cast<bool>(nil::crypto3::verify_share<SecretSharingScheme>(first, last, share)));
            return privkey_type(share);
        }

        //
        // PublicCoeffsRange - public representation values of polynomial's coefficients
        //
        template<typename Scheme, typename PublicCoeffsRange, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType = typename std::iterator_traits<typename PublicCoeffsRange::iterator>::value_type,
                 typename SecretSharingScheme::template check_public_coeff_type<ValueType> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::feldman_sss<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            pubkey::private_key<Scheme>>::type
            create_key(const PublicCoeffsRange &r, typename SecretSharingScheme::share_type share, Number n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRange>));
            return create_key<Scheme>(r.begin(), r.end(), share, n);
        }

        //
        // CoeffsIterator - coefficients of polynomial
        // InputIterator2 - participants' weights
        //
        template<typename Scheme, typename CoeffsIterator, typename WeightsIterator,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<CoeffsIterator>::value_type,
                 typename ValueType2 = typename std::iterator_traits<WeightsIterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_weight_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::weighted_shamir_sss<typename SecretSharingScheme::group_type>,
                         SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(CoeffsIterator first1, CoeffsIterator last1, WeightsIterator first2, WeightsIterator last2) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIterator>));
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<WeightsIterator>));

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

        //
        // CoeffsRange - coefficients of polynomial
        // WeightsRange - participants' weights
        //
        template<typename Scheme, typename CoeffsRange, typename WeightsRange,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<typename CoeffsRange::iterator>::value_type,
                 typename ValueType2 = typename std::iterator_traits<typename WeightsRange::iterator>::value_type,
                 typename SecretSharingScheme::template check_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_weight_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::weighted_shamir_sss<typename SecretSharingScheme::group_type>,
                         SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const CoeffsRange &r1, const WeightsRange &r2) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const CoeffsRange>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const WeightsRange>));
            return create_key<Scheme>(r1.begin(), r1.end(), r2.begin(), r2.end());
        }

        //
        // PublicCoeffsIterators - public representation values of polynomials' coefficients of other participants
        // SharesIterator - shares generated by other participants
        //
        template<typename Scheme, typename PublicCoeffsIterators, typename SharesIterator, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<
                     typename std::iterator_traits<PublicCoeffsIterators>::value_type::iterator>::value_type,
                 typename ValueType2 = typename std::iterator_traits<SharesIterator>::value_type,
                 typename SecretSharingScheme::template check_public_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_share_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::pedersen_dkg<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, pubkey::private_key<Scheme>>>::type
            create_key(PublicCoeffsIterators first1, PublicCoeffsIterators last1, SharesIterator first2,
                       SharesIterator last2, Number n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicCoeffsIterators>));
            BOOST_RANGE_CONCEPT_ASSERT((
                boost::SinglePassRangeConcept<const typename std::iterator_traits<PublicCoeffsIterators>::value_type>));
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<SharesIterator>));
            assert(n == std::distance(first1, last1));
            assert(n == std::distance(first2, last2));

            using privkey_type = pubkey::private_key<Scheme>;

            auto it_coeffs = first1;
            auto it_share = first2;
            typename SecretSharingScheme::public_element_type PK = SecretSharingScheme::public_element_type::zero();
            while (it_coeffs != last1 && it_share != last2) {
                assert(static_cast<bool>(nil::crypto3::verify_share<SecretSharingScheme>(*it_coeffs, *it_share)));
                PK = PK + *((*it_coeffs).begin());
                it_coeffs++;
                it_share++;
            }
            return std::make_pair(pubkey::public_key<Scheme>(PK),
                                  privkey_type(static_cast<typename SecretSharingScheme::share_type>(
                                      nil::crypto3::deal_share<SecretSharingScheme>(first2, last2))));
        }

        //
        // PublicCoeffsRanges - public representation values of polynomials' coefficients of other participants
        // SharesRange - shares generated by other participants
        //
        template<typename Scheme, typename PublicCoeffsRanges, typename SharesRange, typename Number,
                 typename SecretSharingScheme = typename pubkey::private_key<Scheme>::sss_public_key_group_type,
                 typename ValueType1 = typename std::iterator_traits<typename std::iterator_traits<
                     typename PublicCoeffsRanges::iterator>::value_type::iterator>::value_type,
                 typename ValueType2 = typename std::iterator_traits<typename SharesRange::iterator>::value_type,
                 typename SecretSharingScheme::template check_public_coeff_type<ValueType1> = true,
                 typename SecretSharingScheme::template check_share_type<ValueType2> = true>
        inline typename std::enable_if<
            std::is_same<pubkey::pedersen_dkg<typename SecretSharingScheme::group_type>, SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, pubkey::private_key<Scheme>>>::type
            create_key(const PublicCoeffsRanges &r, const SharesRange &shares, Number n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRanges>));
            BOOST_RANGE_CONCEPT_ASSERT(
                (boost::SinglePassRangeConcept<
                    const typename std::iterator_traits<typename PublicCoeffsRanges::iterator>::value_type>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SharesRange>));
            return create_key<Scheme>(r.begin(), r.end(), shares.begin(), shares.end(), n);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard