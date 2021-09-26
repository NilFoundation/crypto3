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

#include <nil/crypto3/pubkey/keys/share_sss.hpp>
#include <nil/crypto3/pubkey/keys/secret_sss.hpp>

#include <nil/crypto3/pubkey/secret_sharing/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Group>
            struct shamir_sss : sss_basic_policy<Group> {
                typedef Group group_type;
                typedef sss_basic_policy<group_type> basic_policy;

                //===========================================================================
                // secret sharing scheme output types

                typedef std::vector<typename basic_policy::coeff_type> coeffs_type;
                typedef std::vector<typename basic_policy::public_coeff_type> public_coeffs_type;

                //
                //  0 <= k < t
                //
                static inline typename basic_policy::share_type
                    partial_eval_share(const typename basic_policy::coeff_type &coeff, std::size_t exp,
                                       const typename basic_policy::share_type &init_share_value) {
                    assert(basic_policy::check_participant_index(init_share_value.first));
                    assert(basic_policy::check_exp(exp));

                    return typename basic_policy::share_type(
                        init_share_value.first,
                        init_share_value.second +
                            coeff * typename basic_policy::private_element_type(init_share_value.first).pow(exp));
                }

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
                typedef typename scheme_type::public_share_type public_share_type;

                public_share_sss() = default;

                public_share_sss(const public_share_type &in_public_share) : public_share(in_public_share) {
                }

                public_share_sss(typename public_share_type::first_type i,
                                 const typename public_share_type::second_type &ps) :
                    public_share(i, ps) {
                }

                inline typename public_share_type::first_type get_index() const {
                    return public_share.first;
                }

                inline typename public_share_type::second_type get_value() const {
                    return public_share.second;
                }

                bool operator==(const public_share_sss &other) const {
                    return this->public_share == other.public_share;
                }

            protected:
                public_share_type public_share;
            };

            template<typename Group>
            struct share_sss<shamir_sss<Group>> : public virtual public_share_sss<shamir_sss<Group>> {
                typedef public_share_sss<shamir_sss<Group>> base_type;
                typedef typename base_type::scheme_type scheme_type;
                typedef typename scheme_type::share_type share_type;

                share_sss(const share_type &in_share) : share_sss(in_share.first, in_share.second) {
                }

                share_sss(typename share_type::first_type i, const typename share_type::second_type &s) :
                    /// no need to call base constructor if dealing of share made by public interface as base type
                    /// will be initialized in accumulator by the call of update_public_share_deal
                    // base_type(i, s * base_type::public_share_type::second_type::one()),
                    share(i, s) {
                }

                inline void update_share_deal(std::size_t exp, const typename scheme_type::coeff_type &coeff) {
                    share.second = scheme_type::partial_eval_share(coeff, exp, share).second;
                }

                inline void update_public_share_deal() {
                    this->public_share.second = share.second * base_type::public_share_type::second_type::one();
                }

                inline typename share_type::first_type get_index() const {
                    return share.first;
                }

                inline typename share_type::second_type get_value() const {
                    return share.second;
                }

                bool operator==(const share_sss &other) const {
                    return this->share == other.share;
                }

            protected:
                share_type share;
            };

            template<typename Group>
            struct secret_sss<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::secret_type secret_type;
                typedef typename scheme_type::indexes_type indexes_type;

                template<typename Shares>
                secret_sss(const Shares &shares, const indexes_type &indexes, std::size_t id_i = 0) :
                    secret_sss(std::cbegin(shares), std::cend(shares), indexes, id_i) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const Shares>));
                }

                template<typename ShareIt>
                secret_sss(ShareIt first, ShareIt last, const indexes_type &indexes, std::size_t id_i = 0) :
                    secret(secret_type::zero()) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    for (auto it = first; it != last; it++) {
                        secret = secret +
                                 it->get_value() * scheme_type::eval_basis_poly(indexes, id_i ? id_i : it->get_index());
                    }
                }

                inline secret_type get_value() const {
                    return secret;
                }

                bool operator==(const secret_sss &other) const {
                    return this->secret == other.secret;
                }

            protected:
                secret_type secret;
            };

            template<typename Group>
            struct deal_shares_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef shares_type internal_accumulator_type;

            protected:
                template<typename Share, typename InternalAccumulator>
                static inline void _init_accumulator(InternalAccumulator &acc, std::size_t n, std::size_t t) {
                    assert(scheme_type::check_threshold_value(t, n));
                    std::size_t i = 1;
                    std::generate_n(std::inserter(acc, std::end(acc)), n,
                                    [&i]() { return Share(i++, Share::share_type::second_type::zero()); });
                }

                template<typename InternalAccumulator>
                static inline void _update(InternalAccumulator &acc, std::size_t exp,
                                           const typename scheme_type::coeff_type &coeff) {
                    for (auto shares_iter = std::begin(acc); shares_iter != std::end(acc); ++shares_iter) {
                        shares_iter->update_share_deal(exp, coeff);
                    }
                }

                template<typename Shares, typename InternalAccumulator>
                static inline Shares _process(InternalAccumulator &acc) {
                    for (auto &share : acc) {
                        share.update_public_share_deal();
                    }
                    return acc;
                }

            public:
                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t) {
                    _init_accumulator<share_type>(acc, n, t);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    _update(acc, exp, coeff);
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return _process<shares_type>(acc);
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<shamir_sss<Group>> {
                typedef shamir_sss<Group> scheme_type;
                typedef typename scheme_type::indexes_type indexes_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::pair<indexes_type, std::vector<share_type>> internal_accumulator_type;

            protected:
                typedef typename share_type::share_type _share_type;
                typedef typename secret_type::secret_type _secret_type;

                template<typename InternalAccumulator, typename Share>
                static inline void _update(InternalAccumulator &acc, const Share &share) {
                    assert(acc.first.emplace(share.get_index()).second);
                    acc.second.push_back(share);
                }

                template<typename Secret, typename InternalAccumulator>
                static inline Secret _process(InternalAccumulator &acc) {
                    return Secret(acc.second, acc.first);
                }

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    _update(acc, share);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return _process<secret_type>(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_SHAMIR_SSS_HPP
