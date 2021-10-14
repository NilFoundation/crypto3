//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
#define CRYPTO3_PUBKEY_SHAMIR_SSS_HPP

#include <vector>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/pubkey/operations/deal_shares_op.hpp>
#include <nil/crypto3/pubkey/operations/reconstruct_secret_op.hpp>
#include <nil/crypto3/pubkey/operations/reconstruct_public_secret_op.hpp>

#include <nil/crypto3/pubkey/keys/share_sss.hpp>
#include <nil/crypto3/pubkey/keys/secret_sss.hpp>
#include <nil/crypto3/pubkey/keys/public_share_sss.hpp>
#include <nil/crypto3/pubkey/keys/public_secret_sss.hpp>

#include <nil/crypto3/pubkey/secret_sharing/weighted_basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct shamir_sss : public sss_weighted_basic_policy<Group> {
                typedef Group group_type;
                typedef sss_basic_policy<group_type> basic_policy;

                //===========================================================================
                // secret sharing scheme output types

                typedef std::vector<typename basic_policy::coeff_type> coeffs_type;
                typedef std::vector<typename basic_policy::public_coeff_type> public_coeffs_type;

                static inline typename basic_policy::private_element_type
                    eval_basis_poly(const typename basic_policy::indexes_type &indexes, std::size_t i) {
                    assert(basic_policy::check_participant_index(i));

                    typename basic_policy::private_element_type e_i(i);
                    typename basic_policy::private_element_type result = basic_policy::private_element_type::one();

                    for (auto j : indexes) {
                        if (j != i) {
                            result = result * (typename basic_policy::private_element_type(j) /
                                               (typename basic_policy::private_element_type(j) - e_i));
                        }
                    }
                    return result;
                }

                //===========================================================================
                // TODO: refactor
                // polynomial generation functions

                static inline coeffs_type get_poly(std::size_t t, std::size_t n) {
                    assert(basic_policy::check_threshold_value(t, n));

                    return get_poly(t);
                }

                template<
                    typename Generator = random::algebraic_random_device<typename basic_policy::coeff_type::field_type>,
                    typename Distribution = void>
                static inline coeffs_type get_poly(std::size_t t) {
                    assert(basic_policy::check_minimal_size(t));

                    coeffs_type coeffs;
                    Generator gen;
                    for (std::size_t i = 0; i < t; i++) {
                        coeffs.emplace_back(gen());
                    }
                    return coeffs;
                }

                //===========================================================================
                // TODO: refactor
                // general purposes functions

                template<typename Coeffs>
                static inline public_coeffs_type get_public_coeffs(const Coeffs &coeffs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Coeffs>));

                    return get_public_coeffs(std::cbegin(coeffs), std::cend(coeffs));
                }

                template<typename CoeffsIt>
                static inline public_coeffs_type get_public_coeffs(CoeffsIt first, CoeffsIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<CoeffsIt>));
                    assert(basic_policy::check_minimal_size(std::distance(first, last)));

                    public_coeffs_type public_coeffs;
                    for (auto it = first; it != last; it++) {
                        public_coeffs.emplace_back(basic_policy::get_public_element(*it));
                    }
                    return public_coeffs;
                }
            };

            template<typename Group>
            struct public_share_sss<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::indexed_public_element_type public_share_type;
                typedef public_share_type data_type;
                typedef typename public_share_type::first_type index_type;
                typedef typename public_share_type::second_type value_type;

                public_share_sss() = default;

                public_share_sss(std::size_t i) : public_share(i, public_share_type::second_type::zero()) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                public_share_sss(const public_share_type &in_public_share) : public_share(in_public_share) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                public_share_sss(std::size_t i, const typename public_share_type::second_type &ps) :
                    public_share(i, ps) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                inline index_type get_index() const {
                    return public_share.first;
                }

                inline const value_type &get_value() const {
                    return public_share.second;
                }

                inline const data_type &get_data() const {
                    return public_share;
                }

                bool operator==(const public_share_sss &other) const {
                    return this->public_share == other.public_share;
                }

                bool operator<(const public_share_sss &other) const {
                    return this->get_index() < other.get_index();
                }

            protected:
                public_share_type public_share;
            };

            template<typename Group>
            struct share_sss<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::indexed_private_element_type share_type;
                typedef share_type data_type;
                typedef typename share_type::first_type index_type;
                typedef typename share_type::second_type value_type;

                share_sss() = default;

                share_sss(std::size_t i) : share(i, share_type::second_type::zero()) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                share_sss(const share_type &in_share) : share(in_share) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                share_sss(std::size_t i, const typename share_type::second_type &s) : share(i, s) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                inline index_type get_index() const {
                    return share.first;
                }

                inline const value_type &get_value() const {
                    return share.second;
                }

                inline const data_type &get_data() const {
                    return share;
                }

                template<
                    typename Scheme,
                    typename std::enable_if<
                        std::is_convertible<typename std::remove_cv<typename std::remove_reference<Scheme>::type>::type,
                                            scheme_type>::value,
                        bool>::type = true>
                operator public_share_sss<Scheme>() const {
                    using To = public_share_sss<Scheme>;

                    return To(share.first, share.second * To::public_share_type::second_type::one());
                }

                bool operator==(const share_sss &other) const {
                    return this->share == other.share;
                }

                bool operator<(const share_sss &other) const {
                    return this->get_index() < other.get_index();
                }

                //
                //  0 <= k < t
                //
                inline void update(const typename scheme_type::coeff_type &coeff, std::size_t exp) {
                    assert(scheme_type::check_exp(exp));

                    share.second =
                        share.second + coeff * typename scheme_type::private_element_type(share.first).pow(exp);
                }

            protected:
                share_type share;
            };

            template<typename Group>
            struct public_secret_sss<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::public_element_type public_secret_type;
                typedef typename scheme_type::indexes_type indexes_type;
                typedef public_secret_type value_type;

                template<typename PublicShares>
                public_secret_sss(const PublicShares &public_shares) :
                    public_secret_sss(std::cbegin(public_shares), std::cend(public_shares)) {
                }

                template<typename PublicShareIt>
                public_secret_sss(PublicShareIt first, PublicShareIt last) :
                    public_secret(reconstruct_public_secret(first, last)) {
                }

                template<typename PublicShares>
                public_secret_sss(const PublicShares &public_shares, const indexes_type &indexes) :
                    public_secret_sss(std::cbegin(public_shares), std::cend(public_shares), indexes) {
                }

                template<typename PublicShareIt>
                public_secret_sss(PublicShareIt first, PublicShareIt last, const indexes_type &indexes) :
                    public_secret(reconstruct_public_secret(first, last, indexes)) {
                }

                inline const value_type &get_value() const {
                    return public_secret;
                }

                bool operator==(const public_secret_sss &other) const {
                    return this->public_secret == other.public_secret;
                }

                bool operator<(const public_secret_sss &other) const {
                    return this->public_secret < other.public_secret;
                }

            private:
                template<
                    typename PublicShareIt,
                    typename std::enable_if<
                        std::is_convertible<typename std::remove_cv<typename std::remove_reference<
                                                typename std::iterator_traits<PublicShareIt>::value_type>::type>::type,
                                            public_share_sss<scheme_type>>::value,
                        bool>::type = true>
                static inline public_secret_type reconstruct_public_secret(PublicShareIt first, PublicShareIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicShareIt>));

                    return reconstruct_public_secret(first, last, scheme_type::get_indexes(first, last));
                }

                template<
                    typename PublicShareIt,
                    typename std::enable_if<
                        std::is_convertible<typename std::remove_cv<typename std::remove_reference<
                                                typename std::iterator_traits<PublicShareIt>::value_type>::type>::type,
                                            public_share_sss<scheme_type>>::value,
                        bool>::type = true>
                static inline public_secret_type reconstruct_public_secret(PublicShareIt first, PublicShareIt last,
                                                                           const indexes_type &indexes) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<PublicShareIt>));

                    public_secret_type public_secret = public_secret_type::zero();
                    for (auto it = first; it != last; it++) {
                        public_secret =
                            public_secret + it->get_value() * scheme_type::eval_basis_poly(indexes, it->get_index());
                    }

                    return public_secret;
                }

                public_secret_type public_secret;
            };

            template<typename Group>
            struct secret_sss<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::private_element_type secret_type;
                typedef typename scheme_type::indexes_type indexes_type;
                typedef secret_type value_type;

                template<typename Shares>
                secret_sss(const Shares &shares) : secret_sss(std::cbegin(shares), std::cend(shares)) {
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last) : secret(reconstruct_secret(first, last)) {
                }

                template<typename Shares>
                secret_sss(const Shares &shares, const indexes_type &indexes) :
                    secret_sss(std::cbegin(shares), std::cend(shares), indexes) {
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last, const indexes_type &indexes) :
                    secret(reconstruct_secret(first, last, indexes)) {
                }

                inline const value_type &get_value() const {
                    return secret;
                }

                bool operator==(const secret_sss &other) const {
                    return this->secret == other.secret;
                }

                bool operator<(const secret_sss &other) const {
                    return this->secret < other.secret;
                }

                template<
                    typename Scheme,
                    typename std::enable_if<
                        std::is_convertible<typename std::remove_cv<typename std::remove_reference<Scheme>::type>::type,
                                            scheme_type>::value,
                        bool>::type = true>
                operator public_secret_sss<Scheme>() const {
                    using To = public_secret_sss<Scheme>;

                    return To(secret * To::public_secret_type::one());
                }

            protected:
                template<typename ShareIt,
                         typename std::enable_if<
                             std::is_convertible<typename std::remove_cv<typename std::remove_reference<
                                                     typename std::iterator_traits<ShareIt>::value_type>::type>::type,
                                                 share_sss<scheme_type>>::value,
                             bool>::type = true>
                static inline secret_type reconstruct_secret(ShareIt first, ShareIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    return reconstruct_secret(first, last, scheme_type::get_indexes(first, last));
                }

                template<typename ShareIt,
                         typename std::enable_if<
                             std::is_convertible<typename std::remove_cv<typename std::remove_reference<
                                                     typename std::iterator_traits<ShareIt>::value_type>::type>::type,
                                                 share_sss<scheme_type>>::value,
                             bool>::type = true>
                static inline secret_type reconstruct_secret(ShareIt first, ShareIt last, const indexes_type &indexes) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    secret_type secret = secret_type::zero();
                    for (auto it = first; it != last; it++) {
                        secret = secret + it->get_value() * scheme_type::eval_basis_poly(indexes, it->get_index());
                    }

                    return secret;
                }

                secret_type secret;
            };

            template<typename Group>
            struct deal_shares_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef shares_type internal_accumulator_type;
                typedef shares_type result_type;

            protected:
                template<typename Share, typename InternalAccumulator>
                static inline void _init_accumulator(InternalAccumulator &acc, std::size_t n, std::size_t t) {
                    assert(scheme_type::check_threshold_value(t, n));

                    std::size_t i = 1;
                    std::generate_n(std::inserter(acc, std::end(acc)), n, [&i]() { return Share(i++); });
                }

                template<typename Scheme, typename InternalAccumulator>
                static inline void _update(InternalAccumulator &acc, std::size_t exp,
                                           const typename Scheme::coeff_type &coeff) {
                    for (auto shares_iter = std::begin(acc); shares_iter != std::end(acc); ++shares_iter) {
                        shares_iter->update(coeff, exp);
                    }
                }

                template<typename ResultType, typename InternalAccumulator>
                static inline ResultType _process(InternalAccumulator &acc) {
                    return acc;
                }

            public:
                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t) {
                    _init_accumulator<share_type>(acc, n, t);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    _update<scheme_type>(acc, exp, coeff);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return _process<result_type>(acc);
                }
            };

            template<typename Group>
            struct reconstruct_public_secret_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef public_share_sss<scheme_type> public_share_type;
                typedef public_secret_sss<scheme_type> public_secret_type;
                typedef std::pair<typename scheme_type::indexes_type, std::set<public_share_type>>
                    internal_accumulator_type;
                typedef public_secret_type result_type;

            protected:
                template<typename InternalAccumulator, typename PublicShare>
                static inline void _update(InternalAccumulator &acc, const PublicShare &public_share) {
                    bool emplace_status = acc.first.emplace(public_share.get_index()).second;
                    assert(emplace_status);
                    // acc.second.push_back(public_share);
                    emplace_status = acc.second.emplace(public_share).second;
                    assert(emplace_status);
                }

                template<typename ResultType, typename InternalAccumulator>
                static inline ResultType _process(InternalAccumulator &acc) {
                    return ResultType(acc.second /*, acc.first*/);
                }

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const public_share_type &public_share) {
                    _update(acc, public_share);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return _process<result_type>(acc);
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::pair<typename scheme_type::indexes_type, std::set<share_type>> internal_accumulator_type;
                typedef secret_type result_type;

            protected:
                template<typename InternalAccumulator, typename Share>
                static inline void _update(InternalAccumulator &acc, const Share &share) {
                    bool emplace_status = acc.first.emplace(share.get_index()).second;
                    assert(emplace_status);
                    // acc.second.push_back(public_share);
                    emplace_status = acc.second.emplace(share).second;
                    assert(emplace_status);
                }

                template<typename ResultType, typename InternalAccumulator>
                static inline ResultType _process(InternalAccumulator &acc) {
                    return ResultType(acc.second /*, acc.first*/);
                }

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    _update(acc, share);
                }

                static inline result_type process(internal_accumulator_type &acc) {
                    return _process<result_type>(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
