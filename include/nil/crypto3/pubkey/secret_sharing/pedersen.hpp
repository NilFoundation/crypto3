//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
#define CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP

#include <nil/crypto3/pubkey/secret_sharing/feldman.hpp>
#include <nil/crypto3/pubkey/operations/deal_share_op.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            //
            // "A threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
            // https://dl.acm.org/citation.cfm?id=1754929
            //
            template<typename Group>
            struct pedersen_dkg : public feldman_sss<Group> {
                typedef feldman_sss<Group> base_type;
            };

            template<typename Group>
            struct public_share_sss<pedersen_dkg<Group>> {
                typedef pedersen_dkg<Group> scheme_type;
                typedef typename scheme_type::indexed_public_element_type public_share_type;

                public_share_sss() = default;

                public_share_sss(typename public_share_type::first_type i) :
                    public_share(i, public_share_type::second_type::zero()) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                public_share_sss(const public_share_type &in_public_share) : public_share(in_public_share) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                public_share_sss(typename public_share_type::first_type i,
                                 const typename public_share_type::second_type &ps) :
                    public_share(i, ps) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                inline typename public_share_type::first_type get_index() const {
                    return public_share.first;
                }

                inline const typename public_share_type::second_type &get_value() const {
                    return public_share.second;
                }

                bool operator==(const public_share_sss &other) const {
                    return this->public_share == other.public_share;
                }

                //
                //  0 <= k < t
                //
                inline void update(const typename scheme_type::public_coeff_type &public_coeff, std::size_t exp) {
                    assert(scheme_type::check_exp(exp));

                    public_share.second =
                        public_share.second +
                        typename scheme_type::private_element_type(public_share.first).pow(exp) * public_coeff;
                }

            private:
                public_share_type public_share;
            };

            template<typename Group>
            struct share_sss<pedersen_dkg<Group>> {
                typedef pedersen_dkg<Group> scheme_type;
                typedef typename scheme_type::indexed_private_element_type share_type;

                share_sss() = default;

                share_sss(typename share_type::first_type i) : share(i, share_type::second_type::zero()) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                share_sss(const share_type &in_share) : share(in_share) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                share_sss(typename share_type::first_type i, const typename share_type::second_type &s) : share(i, s) {
                    assert(scheme_type::check_participant_index(get_index()));
                }

                inline typename share_type::first_type get_index() const {
                    return share.first;
                }

                inline const typename share_type::second_type &get_value() const {
                    return share.second;
                }

                operator public_share_sss<scheme_type>() const {
                    using To = public_share_sss<scheme_type>;

                    return To(share.first, share.second * To::public_share_type::second_type::one());
                }

                bool operator==(const share_sss &other) const {
                    return this->share == other.share;
                }

                //
                //  0 <= k < t
                //
                inline void update(const typename scheme_type::coeff_type &coeff, std::size_t exp) {
                    assert(scheme_type::check_exp(exp));

                    share.second =
                        share.second + coeff * typename scheme_type::private_element_type(share.first).pow(exp);
                }

                inline void update(const share_sss &renewing_share) {
                    assert(renewing_share.get_index() == share.first);

                    share.second = share.second + renewing_share.get_value();
                }

            private:
                share_type share;
            };

            template<typename Group>
            struct secret_sss<pedersen_dkg<Group>> {
                typedef pedersen_dkg<Group> scheme_type;
                typedef typename scheme_type::private_element_type secret_type;
                typedef typename scheme_type::indexes_type indexes_type;

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

                inline const secret_type &get_value() const {
                    return secret;
                }

                bool operator==(const secret_sss &other) const {
                    return this->secret == other.secret;
                }

            private:
                template<typename ShareIt>
                static inline secret_type reconstruct_secret(ShareIt first, ShareIt last) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<ShareIt>));

                    return reconstruct_secret(first, last, scheme_type::get_indexes(first, last));
                }

                template<typename ShareIt,
                         typename std::enable_if<
                             std::is_same<typename std::remove_cv<typename std::remove_reference<
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
            struct deal_shares_op<pedersen_dkg<Group>> : public deal_shares_op<shamir_sss<Group>> {
                typedef deal_shares_op<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef std::vector<share_type> shares_type;
                typedef shares_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t n, std::size_t t) {
                    base_type::template _init_accumulator<share_type>(acc, n, t);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::coeff_type &coeff) {
                    base_type::template _update<scheme_type>(acc, exp, coeff);
                }

                static inline shares_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<shares_type>(acc);
                }
            };

            template<typename Group>
            struct deal_share_op<pedersen_dkg<Group>> {
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef share_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    acc = internal_accumulator_type(i);
                }

                static inline void update(internal_accumulator_type &acc, const share_type &renewing_share) {
                    acc.update(renewing_share);
                }

                static inline share_type process(const internal_accumulator_type &acc) {
                    return acc;
                }
            };

            template<typename Group>
            struct verify_share_op<pedersen_dkg<Group>> : public verify_share_op<feldman_sss<Group>> {
                typedef verify_share_op<feldman_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef public_share_sss<scheme_type> public_share_type;
                typedef public_share_type internal_accumulator_type;

                static inline void init_accumulator(internal_accumulator_type &acc, std::size_t i) {
                    base_type::_init_accumulator(acc, i);
                }

                static inline void update(internal_accumulator_type &acc, std::size_t exp,
                                          const typename scheme_type::public_coeff_type &public_coeff) {
                    base_type::template _update<scheme_type>(acc, exp, public_coeff);
                }

                static inline bool process(const internal_accumulator_type &acc,
                                           const public_share_type &verified_public_share) {
                    return base_type::_process(acc, verified_public_share);
                }
            };

            template<typename Group>
            struct reconstruct_secret_op<pedersen_dkg<Group>> : public reconstruct_secret_op<shamir_sss<Group>> {
                typedef reconstruct_secret_op<shamir_sss<Group>> base_type;
                typedef pedersen_dkg<Group> scheme_type;
                typedef share_sss<scheme_type> share_type;
                typedef secret_sss<scheme_type> secret_type;
                typedef std::pair<typename scheme_type::indexes_type, std::vector<share_type>>
                    internal_accumulator_type;

            public:
                static inline void init_accumulator() {
                }

                static inline void update(internal_accumulator_type &acc, const share_type &share) {
                    base_type::_update(acc, share);
                }

                static inline secret_type process(internal_accumulator_type &acc) {
                    return base_type::template _process<secret_type>(acc);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_PEDERSEN_DKG_HPP
