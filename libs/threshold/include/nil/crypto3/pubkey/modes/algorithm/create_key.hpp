//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/pubkey/type_traits.hpp>

#include <nil/crypto3/pubkey/secret_sharing/pedersen.hpp>
#include <nil/crypto3/pubkey/secret_sharing/weighted_shamir.hpp>

#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/modes/part_public_key.hpp>

#include <nil/crypto3/pubkey/algorithm/deal_shares.hpp>
#include <nil/crypto3/pubkey/algorithm/deal_share.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_share.hpp>

namespace nil {
    namespace crypto3 {
        //
        // CoeffIt - coefficients of polynomial
        //
        template<typename Scheme, typename CoeffIt,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<
            pubkey::is_shamir_sss<SecretSharingScheme>::value || pubkey::is_feldman_sss<SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(CoeffIt first, CoeffIt last, std::size_t n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffIt>));

            using shares_dealing_mode = typename pubkey::modes::isomorphic<SecretSharingScheme>::template bind<
                pubkey::shares_dealing_policy<SecretSharingScheme>>::type;

            typename shares_dealing_mode::result_type shares = deal_shares<SecretSharingScheme>(first, last, n);
            std::vector<pubkey::private_key<Scheme>> privkeys;
            for (const auto &s : shares) {
                privkeys.emplace_back(s);
            }
            auto PK = pubkey::public_key<Scheme>(SecretSharingScheme::get_public_coeffs(first, last).front());
            return std::make_pair(PK, privkeys);
        }

        //
        // Coeffs - coefficients of polynomial
        //
        template<typename Scheme, typename Coeffs,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<
            pubkey::is_shamir_sss<SecretSharingScheme>::value || pubkey::is_feldman_sss<SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const Coeffs &r, std::size_t n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

            return create_key<Scheme>(std::cbegin(r), std::cend(r), n);
        }

        //
        // PublicCoeffIt - public representation values of polynomial's coefficients
        //
        template<typename Scheme, typename PublicCoeffIt,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<pubkey::is_feldman_sss<SecretSharingScheme>::value,
                                       pubkey::private_key<Scheme>>::type
            create_key(PublicCoeffIt first, PublicCoeffIt last, const pubkey::share_sss<SecretSharingScheme> &share,
                       std::size_t n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicCoeffIt>));
            assert(static_cast<bool>(nil::crypto3::verify_share<SecretSharingScheme>(first, last, share)));

            return pubkey::private_key<Scheme>(share);
        }

        //
        // PublicCoeffs - public representation values of polynomial's coefficients
        //
        template<typename Scheme, typename PublicCoeffs,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<pubkey::is_feldman_sss<SecretSharingScheme>::value,
                                       pubkey::private_key<Scheme>>::type
            create_key(const PublicCoeffs &r, pubkey::share_sss<SecretSharingScheme> &share, std::size_t n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffs>));
            return create_key<Scheme>(std::cbegin(r), std::cend(r), share, n);
        }

        //
        // PublicCoeffIt - public representation values of polynomials' coefficients of other participants
        // ShareIt - shares generated by other participants
        //
        template<typename Scheme, typename PublicCoeffsIt, typename ShareIt,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<pubkey::is_pedersen_dkg<SecretSharingScheme>::value,
                                       std::pair<pubkey::public_key<Scheme>, pubkey::private_key<Scheme>>>::type
            create_key(PublicCoeffsIt first1, PublicCoeffsIt last1, ShareIt first2, ShareIt last2, std::size_t n) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicCoeffsIt>));
            BOOST_RANGE_CONCEPT_ASSERT(
                (boost::SinglePassRangeConcept<const typename std::iterator_traits<PublicCoeffsIt>::value_type>));
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));
            assert(n == std::distance(first1, last1));
            assert(n == std::distance(first2, last2));

            using share_dealing_mode = typename pubkey::modes::isomorphic<SecretSharingScheme>::template bind<
                pubkey::share_dealing_policy<SecretSharingScheme>>::type;

            std::size_t t = std::distance(std::cbegin(*first1), std::cend(*first1));
            auto public_coeffs_it = first1;
            auto share_it = first2;
            typename SecretSharingScheme::public_element_type PK = SecretSharingScheme::public_element_type::zero();
            while (public_coeffs_it != last1 && share_it != last2) {
                assert(t == std::distance(std::cbegin(*public_coeffs_it), std::cend(*public_coeffs_it)));
                assert(
                    static_cast<bool>(nil::crypto3::verify_share<SecretSharingScheme>(*public_coeffs_it, *share_it)));
                PK = PK + *(std::cbegin(*public_coeffs_it));
                ++public_coeffs_it;
                ++share_it;
            }
            return std::make_pair(
                pubkey::public_key<Scheme>(PK),
                pubkey::private_key<Scheme>(static_cast<typename share_dealing_mode::result_type>(
                    nil::crypto3::deal_share<SecretSharingScheme>(first2->get_index(), first2, last2))));
        }

        //
        // PublicCoeffsRange - public representation values of polynomials' coefficients of other participants
        // Shares - shares generated by other participants
        //
        template<typename Scheme, typename PublicCoeffsRange, typename Shares,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<pubkey::is_pedersen_dkg<SecretSharingScheme>::value,
                                       std::pair<pubkey::public_key<Scheme>, pubkey::private_key<Scheme>>>::type
            create_key(const PublicCoeffsRange &r, const Shares &shares, std::size_t n) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const PublicCoeffsRange>));
            BOOST_RANGE_CONCEPT_ASSERT(
                (boost::SinglePassRangeConcept<
                    const typename std::iterator_traits<typename PublicCoeffsRange::iterator>::value_type>));
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));

            return create_key<Scheme>(std::cbegin(r), std::cend(r), std::cbegin(shares), std::cend(shares), n);
        }

        //
        // CoeffIt - coefficients of polynomial
        // InputIterator2 - participants' weights
        //
        template<typename Scheme, typename CoeffIt,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<
            pubkey::is_weighted_shamir_sss<SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(CoeffIt first1, CoeffIt last1, std::size_t n, const typename SecretSharingScheme::weights_type &weights) {
            BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffIt>));

            using shares_dealing_mode = typename pubkey::modes::isomorphic<SecretSharingScheme>::template bind<
                pubkey::shares_dealing_policy<SecretSharingScheme>>::type;

            typename shares_dealing_mode::result_type shares = nil::crypto3::deal_shares<SecretSharingScheme>(
                first1, last1, n, weights);
            std::vector<pubkey::private_key<Scheme>> privkeys;
            for (const auto &s : shares) {
                privkeys.emplace_back(s);
            }
            auto PK = pubkey::public_key<Scheme>(SecretSharingScheme::get_public_coeffs(first1, last1).front());
            return std::make_pair(PK, privkeys);
        }

        //
        // Coeffs - coefficients of polynomial
        // WeightsRange - participants' weights
        //
        template<typename Scheme, typename Coeffs,
                 typename SecretSharingScheme = typename pubkey::public_key<Scheme>::sss_public_key_group_type>
        inline typename std::enable_if<
            pubkey::is_weighted_shamir_sss<SecretSharingScheme>::value,
            std::pair<pubkey::public_key<Scheme>, std::vector<pubkey::private_key<Scheme>>>>::type
            create_key(const Coeffs &r1, std::size_t n, const typename SecretSharingScheme::weights_type &weights) {
            BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

            return create_key<Scheme>(std::cbegin(r1), std::cend(r1), n, weights);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard