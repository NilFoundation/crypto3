//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PK_PAD_EMSA1_HPP
#define CRYPTO3_PK_PAD_EMSA1_HPP

#include <iterator>
#include <type_traits>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/marshalling/algorithms/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                namespace detail {
                    template<typename MsgReprType, typename Hash, typename = void>
                    struct emsa1_encoding_policy;

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_encoding_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<
                            algebra::is_field<typename MsgReprType::field_type>::value &&
                            !algebra::is_extended_field<typename MsgReprType::field_type>::value>::type> {
                        typedef Hash hash_type;

                    protected:
                        typedef typename MsgReprType::field_type field_type;

                        constexpr static std::size_t digest_bits = hash_type::digest_bits;

                        constexpr static std::size_t modulus_bits = field_type::modulus_bits;
                        constexpr static std::size_t modulus_octets =
                            modulus_bits / 8 + static_cast<std::size_t>(modulus_bits % 8 != 0);

                        typedef std::array<std::uint8_t, modulus_octets> modulus_octets_container_type;

                    public:
                        typedef MsgReprType msg_repr_type;
                        typedef accumulator_set<hash_type> internal_accumulator_type;
                        typedef msg_repr_type result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                        }

                        template<typename InputRange>
                        static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                            hash<hash_type>(range, acc);
                        }

                        template<typename InputIterator>
                        static inline void update(internal_accumulator_type &acc, InputIterator first,
                                                  InputIterator last) {
                            hash<hash_type>(first, last, acc);
                        }

                        template<std::size_t DigistBits = digest_bits, std::size_t ModulusBits = modulus_bits,
                                 typename std::enable_if<(DigistBits >= ModulusBits), bool>::type = true>
                        static inline result_type process(internal_accumulator_type &acc) {
                            typename hash_type::digest_type digest =
                                ::nil::crypto3::accumulators::extract::hash<hash_type>(acc);

                            nil::marshalling::status_type status;
                            return ::nil::marshalling::pack<::nil::marshalling::option::big_endian>(digest, status);
                        }

                        template<std::size_t DigistBits = digest_bits, std::size_t ModulusBits = modulus_bits,
                                 typename std::enable_if<(DigistBits < ModulusBits), bool>::type = true>
                        static inline result_type process(internal_accumulator_type &acc) {
                            typename hash_type::digest_type digest =
                                ::nil::crypto3::accumulators::extract::hash<hash_type>(acc);
                            // TODO: creating copy of digest range of modulus_octets size is a bottleneck:
                            //  extend marshalling interface by function supporting initialization from container which
                            //  length is less than modulus_octets
                            modulus_octets_container_type modulus_octets_container;
                            modulus_octets_container.fill(0);
                            std::copy(std::crbegin(digest), std::crend(digest), std::rbegin(modulus_octets_container));

                            nil::marshalling::status_type status;
                            return ::nil::marshalling::pack<::nil::marshalling::option::big_endian>(
                                modulus_octets_container, status);
                        }
                    };

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_encoding_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<
                            algebra::is_field<MsgReprType>::value &&
                            !algebra::is_extended_field<typename MsgReprType::field_type>::value>::type>
                        : public emsa1_encoding_policy<typename MsgReprType::value_type, Hash> { };

                    template<typename MsgReprType, typename Hash, typename = void>
                    struct emsa1_verification_policy;

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_verification_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<
                            algebra::is_field<typename MsgReprType::field_type>::value &&
                            !algebra::is_extended_field<typename MsgReprType::field_type>::value>::type> {
                    protected:
                        typedef typename MsgReprType::field_type field_type;
                        typedef emsa1_encoding_policy<MsgReprType, Hash> encoding_policy;

                    public:
                        typedef Hash hash_type;
                        typedef MsgReprType msg_repr_type;
                        typedef typename encoding_policy::internal_accumulator_type internal_accumulator_type;
                        typedef bool result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                            encoding_policy::init_accumulator(acc);
                        }

                        template<typename InputRange>
                        static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                            encoding_policy::update(range, acc);
                        }

                        template<typename InputIterator>
                        static inline void update(internal_accumulator_type &acc, InputIterator first,
                                                  InputIterator last) {
                            encoding_policy::update(first, last, acc);
                        }

                        static inline result_type process(internal_accumulator_type &acc,
                                                          const msg_repr_type &msg_repr) {
                            return encoding_policy::process(acc) == msg_repr;
                        }
                    };

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_verification_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<
                            algebra::is_field<MsgReprType>::value &&
                            !algebra::is_extended_field<typename MsgReprType::field_type>::value>::type>
                        : public emsa1_verification_policy<typename MsgReprType::value_type, Hash> { };

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_encoding_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<std::is_same<typename Hash::digest_type, MsgReprType>::value>::type> {
                        typedef Hash hash_type;
                        typedef MsgReprType msg_repr_type;
                        typedef accumulator_set<hash_type> internal_accumulator_type;
                        typedef msg_repr_type result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                        }

                        template<typename InputRange>
                        static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                            hash<hash_type>(range, acc);
                        }

                        template<typename InputIterator>
                        static inline void update(internal_accumulator_type &acc, InputIterator first,
                                                  InputIterator last) {
                            hash<hash_type>(first, last, acc);
                        }

                        static inline result_type process(internal_accumulator_type &acc) {
                            return ::nil::crypto3::accumulators::extract::hash<hash_type>(acc);
                        }
                    };

                    template<typename MsgReprType, typename Hash>
                    struct emsa1_verification_policy<
                        MsgReprType, Hash,
                        typename std::enable_if<std::is_same<typename Hash::digest_type, MsgReprType>::value>::type> {
                    protected:
                        typedef emsa1_encoding_policy<MsgReprType, Hash> encoding_policy;

                    public:
                        typedef Hash hash_type;
                        typedef MsgReprType msg_repr_type;
                        typedef typename encoding_policy::internal_accumulator_type internal_accumulator_type;
                        typedef bool result_type;

                        static inline void init_accumulator(internal_accumulator_type &acc) {
                            encoding_policy::init_accumulator(acc);
                        }

                        template<typename InputRange>
                        static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                            encoding_policy::update(range, acc);
                        }

                        template<typename InputIterator>
                        static inline void update(internal_accumulator_type &acc, InputIterator first,
                                                  InputIterator last) {
                            encoding_policy::update(first, last, acc);
                        }

                        static inline result_type process(internal_accumulator_type &acc,
                                                          const msg_repr_type &msg_repr) {
                            return encoding_policy::process(acc) == msg_repr;
                        }
                    };
                }    // namespace detail

                /*!
                 * @brief EMSA1 from IEEE 1363.
                 * Essentially, sign the hash directly
                 *
                 * @tparam MsgReprType
                 * @tparam Hash
                 * @tparam l
                 */
                template<typename MsgReprType, typename Hash, typename Params = void>
                struct emsa1 {
                    typedef MsgReprType msg_repr_type;
                    typedef Hash hash_type;

                    typedef detail::emsa1_encoding_policy<MsgReprType, Hash> encoding_policy;
                    typedef detail::emsa1_verification_policy<MsgReprType, Hash> verification_policy;
                };
            }    // namespace padding
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PK_PAD_EMSA1_HPP
