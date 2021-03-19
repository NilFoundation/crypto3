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

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

#include <map>
#include <vector>
#include <iterator>
#include <type_traits>
#include <utility>
#include <functional>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/mpl/vector.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/detail/bls/bls_basic_policy.hpp>
#include <nil/crypto3/pubkey/detail/bls/bls_core_functions.hpp>
#include <nil/crypto3/pubkey/detail/stream_processor.hpp>
#include <nil/crypto3/pubkey/pk_keys.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                struct bls_public_params {
                    typedef std::vector<std::uint8_t> dst_type;

                    template<typename InputRange,
                             typename = typename std::enable_if<std::is_same<
                                 typename dst_type::value_type, typename InputRange::value_type>::value>::type>
                    bls_public_params(const InputRange &in_dst) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputRange>));

                        std::copy(in_dst.cbegin(), in_dst.cend(), std::back_inserter(dst));
                    }

                    dst_type dst;
                };

                struct bls_pop_public_params : bls_public_params {
                    typedef std::vector<std::uint8_t> pop_dst_type;

                    template<typename InputRange1, typename InputRange2,
                             typename = typename std::enable_if<
                                 std::is_same<typename dst_type::value_type, typename InputRange1::value_type>::value &&
                                 std::is_same<typename pop_dst_type::value_type,
                                              typename InputRange2::value_type>::value>::type>
                    bls_pop_public_params(const InputRange1 &in_dst, const InputRange2 &in_pop_dst) :
                        bls_public_params(in_dst) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputRange2>));

                        std::copy(in_pop_dst.cbegin(), in_pop_dst.cend(), std::back_inserter(pop_dst));
                    }

                    pop_dst_type pop_dst;
                };

                //
                // Basic scheme
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.1
                //
                template<typename SignatureVariant>
                struct bls_basic_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;
                    typedef bls_public_params public_params_type;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;
                    typedef typename policy_type::pubkey_id_type pubkey_id_type;

                    template<typename MsgRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const public_params_type &pp) {
                        return sign(privkey, message, pp.dst);
                    }

                    // //
                    // // Sign, then aggregate
                    // //
                    // template<typename MsgRange, typename SignatureRange>
                    // static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                    //                                   const SignatureRange &signatures, const public_params_type &pp)
                    //                                   {
                    //     return aggregate(sign(privkey, message, pp), signatures);
                    // }

                    template<typename MsgRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const signature_type &signature, const public_params_type &pp) {
                        return verify(pubkey, message, pp.dst, signature);
                    }

                    template<typename PubkeyRange, typename MsgRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgRange &messages,
                                                        const signature_type &signature, const public_params_type &pp) {
                        return aggregate_verify(pubkeys, messages, pp.dst, signature);
                    }

                    static inline pubkey_id_type get_pubkey_bits(const public_key_type &pubkey) {
                        return core_functions::get_pubkey_bits(pubkey);
                    }

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                    // protected:
                    template<typename MsgRange, typename DstRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const DstRange &dst) {
                        return core_functions::core_sign(privkey, message, dst);
                    }

                    template<typename MsgRange, typename DstRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const DstRange &dst, const signature_type &signature) {
                        return core_functions::core_verify(pubkey, message, dst, signature);
                    }

                    static inline signature_type aggregate(const signature_type &init_signature,
                                                           const signature_type &signature) {
                        return core_functions::core_aggregate(init_signature, signature);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const SignatureRange &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const signature_type &init_signature,
                                                           const SignatureRange &signatures) {
                        return core_functions::core_aggregate(init_signature, signatures);
                    }

                    template<typename PubkeyRange, typename MsgsRange, typename DstRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgsRange &messages,
                                                        const DstRange &dst, const signature_type &signature) {
                        // TODO: add check - If any two input messages are equal, return INVALID.
                        return core_functions::core_aggregate_verify(pubkeys, messages, dst, signature);
                    }
                };

                //
                // Message augmentation
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.2
                //
                template<typename SignatureVariant>
                struct bls_aug_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;
                    typedef bls_public_params public_params_type;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;
                    typedef typename policy_type::pubkey_id_type pubkey_id_type;

                    template<typename MsgRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const public_params_type &pp) {
                        return sign(privkey, message, pp.dst);
                    }

                    template<typename MsgRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const signature_type &signature, const public_params_type &pp) {
                        return verify(pubkey, message, pp.dst, signature);
                    }

                    template<typename PubkeyRange, typename MsgRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgRange &messages,
                                                        const signature_type &signature, const public_params_type &pp) {
                        return aggregate_verify(pubkeys, messages, pp.dst, signature);
                    }

                    static inline pubkey_id_type get_pubkey_bits(const public_key_type &pubkey) {
                        return core_functions::get_pubkey_bits(pubkey);
                    }

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                    // protected:
                    // TODO: implement an interface that takes the public key as input
                    template<typename MsgRange, typename DstRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const DstRange &dst) {
                        public_key_type pubkey = generate_public_key(privkey);
                        return core_functions::core_sign(privkey, core_functions::pk_conc_msg(pubkey, message), dst);
                    }

                    template<typename MsgRange, typename DstRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const DstRange &dst, const signature_type &signature) {
                        return core_functions::core_verify(pubkey, core_functions::pk_conc_msg(pubkey, message), dst,
                                                           signature);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const SignatureRange &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const signature_type &init_signature,
                                                           const SignatureRange &signatures) {
                        return core_functions::core_aggregate(init_signature, signatures);
                    }

                    template<typename PubkeyRange, typename MsgsRange, typename DstRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgsRange &messages,
                                                        const DstRange &dst, const signature_type &signature) {
                        return core_functions::aug_aggregate_verify(pubkeys, messages, dst, signature);
                    }
                };

                //
                // Proof of possession
                // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-3.3
                //
                template<typename SignatureVariant>
                struct bls_pop_scheme {
                    typedef SignatureVariant signature_variant;
                    typedef typename signature_variant::policy_type policy_type;
                    typedef typename signature_variant::core_functions core_functions;
                    typedef bls_pop_public_params public_params_type;

                    typedef typename policy_type::private_key_type private_key_type;
                    typedef typename policy_type::public_key_type public_key_type;
                    typedef typename policy_type::signature_type signature_type;
                    typedef typename policy_type::pubkey_id_type pubkey_id_type;

                    template<typename MsgRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const public_params_type &pp) {
                        return sign(privkey, message, pp.dst);
                    }

                    template<typename MsgRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const signature_type &signature, const public_params_type &pp) {
                        return verify(pubkey, message, pp.dst, signature);
                    }

                    template<typename PubkeyRange, typename MsgRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgRange &messages,
                                                        const signature_type &signature, const public_params_type &pp) {
                        return aggregate_verify(pubkeys, messages, pp.dst, signature);
                    }

                    static inline pubkey_id_type get_pubkey_bits(const public_key_type &pubkey) {
                        return core_functions::get_pubkey_bits(pubkey);
                    }

                    static inline public_key_type generate_public_key(const private_key_type &privkey) {
                        return core_functions::sk_to_pk(privkey);
                    }

                    static inline signature_type pop_prove(const private_key_type &privkey,
                                                           const public_params_type &pp) {
                        return core_functions::pop_prove(privkey, pp.pop_dst);
                    }

                    static inline bool pop_verify(const public_key_type &pubkey, const public_params_type &pp,
                                                  const signature_type &proof) {
                        return core_functions::pop_verify(pubkey, pp.pop_dst, proof);
                    }

                    template<typename PubkeyRange, typename MsgRange>
                    static inline bool fast_aggregate_verify(const PubkeyRange &pubkeys, const MsgRange &message,
                                                             const public_params_type &pp,
                                                             const signature_type &signature) {
                        return core_functions::fast_aggregate_verify(pubkeys, message, pp.dst, signature);
                    }

                    // protected:
                    template<typename MsgRange, typename DstRange>
                    static inline signature_type sign(const private_key_type &privkey, const MsgRange &message,
                                                      const DstRange &dst) {
                        return core_functions::core_sign(privkey, message, dst);
                    }

                    template<typename MsgRange, typename DstRange>
                    static inline bool verify(const public_key_type &pubkey, const MsgRange &message,
                                              const DstRange &dst, const signature_type &signature) {
                        return core_functions::core_verify(pubkey, message, dst, signature);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const SignatureRange &signatures) {
                        return core_functions::core_aggregate(signatures);
                    }

                    template<typename SignatureRange>
                    static inline signature_type aggregate(const signature_type &init_signature,
                                                           const SignatureRange &signatures) {
                        return core_functions::core_aggregate(init_signature, signatures);
                    }

                    template<typename PubkeyRange, typename MsgsRange, typename DstRange>
                    static inline bool aggregate_verify(const PubkeyRange &pubkeys, const MsgsRange &messages,
                                                        const DstRange &dst, const signature_type &signature) {
                        return core_functions::core_aggregate_verify(pubkeys, messages, dst, signature);
                    }

                    // TODO: implement an interface that takes the public key as input
                    template<typename PopDstType>
                    static inline signature_type pop_prove(const private_key_type &privkey, const PopDstType &dst) {
                        return core_functions::pop_prove(privkey, dst);
                    }

                    template<typename PopDstType>
                    static inline bool pop_verify(const public_key_type &pubkey, const PopDstType &dst,
                                                  const signature_type &proof) {
                        return core_functions::pop_verify(pubkey, dst, proof);
                    }

                    template<typename PubkeyRange, typename MsgRange, typename DstRange>
                    static inline bool fast_aggregate_verify(const PubkeyRange &pubkeys, const MsgRange &message,
                                                             const DstRange &dst, const signature_type &signature) {
                        return core_functions::fast_aggregate_verify(pubkeys, message, dst, signature);
                    }
                };
            }    // namespace detail

            //
            // Minimal-signature-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_mss_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mss_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> core_functions;
            };

            //
            // Minimal-pubkey-size
            // Random oracle version of hash-to-point
            //
            template<typename CurveType = algebra::curves::bls12_381, typename HashType = hashes::sha2<256>>
            struct bls_mps_ro_variant {
                typedef CurveType curve_type;
                typedef HashType hash_type;

                typedef detail::bls_mps_ro_policy<curve_type, hash_type> policy_type;
                typedef detail::bls_core_functions<policy_type> core_functions;
            };

            enum class bls_scheme_enum { basic, aug, pop };

            template<bls_scheme_enum, typename SignatureVariant>
            struct bls_scheme_trait { };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_enum::basic, SignatureVariant> {
                typedef detail::bls_basic_scheme<SignatureVariant> bls_scheme_type;
            };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_enum::aug, SignatureVariant> {
                typedef detail::bls_aug_scheme<SignatureVariant> bls_scheme_type;
            };

            template<typename SignatureVariant>
            struct bls_scheme_trait<bls_scheme_enum::pop, SignatureVariant> {
                typedef detail::bls_pop_scheme<SignatureVariant> bls_scheme_type;
            };

            template<typename SignatureVariant, bls_scheme_enum bls_scheme = bls_scheme_enum::basic>
            struct bls {
                typedef typename bls_scheme_trait<bls_scheme, SignatureVariant>::bls_scheme_type bls_scheme_type;

                typedef typename bls_scheme_type::signature_type signature_type;
                typedef typename bls_scheme_type::public_params_type public_params_type;

                template<typename Mode, typename AccumulatorSet, std::size_t ValueBits = 0>
                struct stream_processor {
                    struct params_type {
                        typedef stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };
                    typedef ::nil::crypto3::pubkey::stream_processor<Mode, AccumulatorSet, params_type> type;
                };
            };

            // TODO: add specialization for pop scheme
            template<typename SignatureVariant, bls_scheme_enum bls_scheme>
            struct public_key<bls<SignatureVariant, bls_scheme>> {
                typedef bls<SignatureVariant, bls_scheme> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;
                typedef typename bls_scheme_type::public_params_type public_params_type;
                typedef typename bls_scheme_type::pubkey_id_type pubkey_id_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                typedef std::pair<public_key, input_block_type> aggregate_value_type;
                typedef std::map<public_key, input_block_type> aggregate_type;

                template<typename AggregateValueType, typename Pubkey = typename AggregateValueType::first_type,
                         typename BlockType = typename AggregateValueType::second_type,
                         typename std::enable_if<std::is_same<public_key, typename std::remove_cv<Pubkey>::type>::value,
                                                 bool>::type = true,
                         typename std::enable_if<std::is_same<input_value_type, typename BlockType::value_type>::value,
                                                 bool>::type = true>
                using check_aggregate_value_type =
                    typename std::enable_if<std::is_same<std::pair<Pubkey, BlockType>, AggregateValueType>::value,
                                            bool>::type;

                template<typename AggregateData>
                using check_aggregate_type = check_aggregate_value_type<typename AggregateData::value_type>;

                public_key() {
                }

                public_key(const public_key_type &pubkey) : pubkey(pubkey) {
                }

                template<typename MsgRange,
                         typename std::enable_if<std::is_same<input_value_type, typename MsgRange::value_type>::value,
                                                 bool>::type = true>
                inline bool verify(const MsgRange &msg, const signature_type &sig, const public_params_type &pp) const {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const MsgRange>));
                    return bls_scheme_type::verify(pubkey, msg, sig, pp);
                }

                // TODO: fix me - std::reference_wrapper seems not to work
                template<typename AggregateData, check_aggregate_type<AggregateData> = true>
                static inline bool aggregate_verify(const AggregateData &agg_data, const signature_type &sig,
                                                    const public_params_type &pp) {
                    using BlockType = typename AggregateData::value_type::second_type;
                    std::vector<std::reference_wrapper<const public_key_type>> pubkeys;
                    std::vector<std::reference_wrapper<const BlockType>> msgs;
                    for (const auto &pubkey_msg : agg_data) {
                        pubkeys.emplace_back(pubkey_msg.first.get_pubkey());
                        msgs.emplace_back(pubkey_msg.second);
                    }
                    return bls_scheme_type::aggregate_verify(pubkeys, msgs, sig, pp);
                }

                inline pubkey_id_type get_pubkey_bits() const {
                    return bls_scheme_type::get_pubkey_bits(pubkey);
                }

                inline const public_key_type &get_pubkey() const {
                    return pubkey;
                }

                inline bool operator<(const public_key &other) const {
                    return get_pubkey_bits() < other.get_pubkey_bits();
                }

                template<typename AggregateData, typename InputIterator,
                         typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                         check_aggregate_type<AggregateData> = true,
                         typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                inline void append_aggregate_data(AggregateData &agg_data, InputIterator first,
                                                  InputIterator last) const {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                    auto count = agg_data.count(pubkey);
                    assert(0 == count || 1 == count);
                    if (!count) {
                        agg_data.emplace(*this, input_block_type(first, last));
                    } else if (1 == count) {
                        std::copy(first, last, std::back_inserter(agg_data.at(*this)));
                    }
                }

                template<typename AggregateData, typename InputBlock, check_aggregate_type<AggregateData> = true,
                         typename std::enable_if<std::is_same<input_value_type, typename InputBlock::value_type>::value,
                                                 bool>::type = true>
                inline void append_aggregate_data(AggregateData &agg_data, const InputBlock &block) const {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const InputBlock>));
                    append_aggregate_data(agg_data, block.cbegin(), block.cend());
                }

                template<typename AggregateData, typename ValueType, check_aggregate_type<AggregateData> = true,
                         typename std::enable_if<std::is_same<input_value_type, ValueType>::value, bool>::type = true>
                inline void append_aggregate_data(AggregateData &agg_data, const ValueType &value) const {
                    auto count = agg_data.count(pubkey);
                    assert(0 == count || 1 == count);
                    if (!count) {
                        agg_data.emplace(*this, input_block_type());
                    }
                    agg_data.at(*this).emplace_back(value);
                }

            protected:
                public_key_type pubkey;
            };

            // TODO: add specialization for pop scheme
            template<typename SignatureVariant, bls_scheme_enum bls_scheme>
            struct private_key<bls<SignatureVariant, bls_scheme>> : public_key<bls<SignatureVariant, bls_scheme>> {
                typedef bls<SignatureVariant, bls_scheme> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;
                typedef public_key<scheme_type> base_type;

                typedef typename base_type::private_key_type private_key_type;
                typedef typename base_type::public_key_type public_key_type;
                typedef typename base_type::signature_type signature_type;
                typedef typename base_type::public_params_type public_params_type;

                typedef std::vector<std::uint8_t> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 8;

                typedef private_key_type key_type;

                // TODO: add default constructor

                private_key(const private_key_type &privkey) :
                    privkey(privkey), base_type(generate_public_key(privkey)) {
                }

                static inline public_key_type generate_public_key(const private_key_type &privkey) {
                    return bls_scheme_type::generate_public_key(privkey);
                }

                template<typename MsgRange,
                         typename std::enable_if<std::is_same<input_value_type, typename MsgRange::value_type>::value,
                                                 bool>::type = true>
                inline signature_type sign(const MsgRange &msg, const public_params_type &pp) const {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const MsgRange>));
                    return bls_scheme_type::sign(privkey, msg, pp);
                }

            protected:
                private_key_type privkey;
            };

            template<typename SignatureVariant, bls_scheme_enum bls_scheme>
            struct no_key_ops<bls<SignatureVariant, bls_scheme>> {
                typedef bls<SignatureVariant, bls_scheme> scheme_type;
                typedef typename scheme_type::bls_scheme_type bls_scheme_type;

                typedef typename bls_scheme_type::private_key_type private_key_type;
                typedef typename bls_scheme_type::public_key_type public_key_type;
                typedef typename bls_scheme_type::signature_type signature_type;

                typedef std::vector<signature_type> input_block_type;
                constexpr static const std::size_t input_block_bits = 0;    // non-restricted length

                typedef typename input_block_type::value_type input_value_type;
                constexpr static const std::size_t input_value_bits = 0;    // non-integral objects

                static inline signature_type aggregate(const signature_type &init_signature,
                                                       const signature_type &signature) {
                    return bls_scheme_type::aggregate(init_signature, signature);
                }

                template<
                    typename SignatureRange,
                    typename std::enable_if<std::is_same<signature_type, typename SignatureRange::value_type>::value,
                                            bool>::type = true>
                static inline signature_type aggregate(const SignatureRange &sigs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SignatureRange>));
                    return bls_scheme_type::aggregate(sigs);
                }

                template<
                    typename SignatureRange,
                    typename std::enable_if<std::is_same<signature_type, typename SignatureRange::value_type>::value,
                                            bool>::type = true>
                static inline signature_type aggregate(const signature_type &init_sig, SignatureRange &sigs) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SignatureRange>));
                    return bls_scheme_type::aggregate(init_sig, sigs);
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_BLS_HPP
