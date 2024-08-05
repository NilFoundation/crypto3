//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
#define CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/h2f.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace transcript {

                /*!
                 * @brief Fiat–Shamir heuristic.
                 * @tparam Hash Hash function, which serves as a non-interactive random oracle.
                 * @tparam TManifest Fiat-Shamir Heuristic Manifest in the following form:
                 *
                 * template<typename ...>
                 * struct fiat_shamir_heuristic_manifest {
                 *
                 *     struct transcript_manifest {
                 *         std::size_t gammas_amount = 5;
                 *       public:
                 *         enum challenges_ids{
                 *             alpha,
                 *             beta,
                 *             gamma = 10,
                 *             delta = gamma + gammas_amount,
                 *             epsilon
                 *         }
                 *
                 *     }
                 * };
                 */
                template<typename ChallengesType, typename Hash>
                class fiat_shamir_heuristic_accumulative {

                    accumulator_set<Hash> acc;

                public:
                    typedef Hash hash_type;
                    typedef ChallengesType challenges_type;

                    fiat_shamir_heuristic_accumulative() : acc() {
                    }

                    template<typename TAny>
                    void operator()(TAny data) {
                        if constexpr (algebra::is_field_element<typename hash_type::word_type>::value) {
                            BOOST_STATIC_ASSERT_MSG(
                                algebra::is_field_element<TAny>::value,
                                "Hash type consumes field elements, but provided value is not a field element");
                            acc(data);
                        } else {
                            nil::marshalling::status_type status;
                            typename hash_type::construction::type::block_type byte_data =
                                nil::marshalling::pack(data, status);
                            acc(byte_data);
                        }
                    }

                    template<typename ChallengesType::challenges_ids ChallengeId, typename FieldType>
                    typename FieldType::value_type challenge() {
                        // acc(ChallengeId);
                        typename hash_type::digest_type hash_res = accumulators::extract::hash<Hash>(acc);

                        return FieldType::value_type::one();
                    }

                    template<typename ChallengesType::challenges_ids ChallengeId, std::size_t Index, typename FieldType>
                    typename FieldType::value_type challenge() {
                        // acc(ChallengeId + Index);
                        typename hash_type::digest_type hash_res = accumulators::extract::hash<Hash>(acc);

                        return FieldType::value_type::one();
                    }

                    template<typename ChallengesType::challenges_ids ChallengeId,
                             std::size_t ChallengesAmount,
                             typename FieldType>
                    std::array<typename FieldType::value_type, ChallengesAmount> challenges() {

                        std::array<typename hash_type::digest_type, ChallengesAmount> hash_results;
                        std::array<typename FieldType::value_type, ChallengesAmount> result;

                        for (std::size_t i = 0; i < ChallengesAmount; i++) {

                            // acc(ChallengeId + i);
                            hash_results[i] = accumulators::extract::hash<hash_type>(acc);
                        }

                        return result;
                    }
                };

                template<typename Hash, typename Enable = void>
                struct fiat_shamir_heuristic_sequential {
                    typedef Hash hash_type;

                    typedef typename boost::multiprecision::cpp_int_modular_backend<hash_type::digest_bits>
                        modular_backend_of_hash_size;

                    fiat_shamir_heuristic_sequential() : state(hash<hash_type>({0})) {
                    }

                    template<typename InputRange>
                    fiat_shamir_heuristic_sequential(const InputRange &r) : state(hash<hash_type>(r)) {
                    }

                    template<typename InputIterator>
                    fiat_shamir_heuristic_sequential(InputIterator first, InputIterator last) :
                        state(hash<hash_type>(first, last)) {
                    }

                    template<typename InputRange>
                    typename std::enable_if_t<!algebra::is_group_element<InputRange>::value &&
                                              !algebra::is_field_element<InputRange>::value>
                        operator()(const InputRange &r) {
                        auto acc_convertible = hash<hash_type>(state);
                        state = accumulators::extract::hash<hash_type>(
                            hash<hash_type>(r, static_cast<accumulator_set<hash_type> &>(acc_convertible)));
                    }

                    template<typename InputIterator>
                    void operator()(InputIterator first, InputIterator last) {
                        auto acc_convertible = hash<hash_type>(state);
                        state = accumulators::extract::hash<hash_type>(
                            hash<hash_type>(first, last, static_cast<accumulator_set<hash_type> &>(acc_convertible)));
                    }

                    template<typename element>
                    typename std::enable_if_t<algebra::is_group_element<element>::value ||
                                              algebra::is_field_element<element>::value>
                        operator()(element const &data) {
                        nil::marshalling::status_type status;
                        std::vector<std::uint8_t> byte_data =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(data, status);
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);
                        auto acc_convertible = hash<hash_type>(state);
                        state = accumulators::extract::hash<hash_type>(
                            hash<hash_type>(byte_data, static_cast<accumulator_set<hash_type> &>(acc_convertible)));
                    }

                    template<typename Field>
                    typename std::enable_if<(Hash::digest_bits >= Field::modulus_bits),
                                            typename Field::value_type>::type
                        challenge() {
                        using digest_value_type = typename hash_type::digest_type::value_type;
                        const std::size_t digest_value_bits = sizeof(digest_value_type) * CHAR_BIT;
                        const std::size_t element_size = Field::number_bits / digest_value_bits +
                                                         (Field::number_bits % digest_value_bits == 0 ? 0 : 1);

                        std::array<digest_value_type, element_size> data;
                        state = hash<hash_type>(state);

                        std::size_t count = std::min(data.size(), state.size());
                        std::copy(state.begin(), state.begin() + count, data.begin() + data.size() - count);

                        nil::marshalling::status_type status;
                        boost::multiprecision::number<modular_backend_of_hash_size> raw_result =
                            nil::marshalling::pack(state, status);
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);

                        return raw_result;
                    }

                    template<typename Field>
                    typename std::enable_if<(Hash::digest_bits < Field::modulus_bits), typename Field::value_type>::type
                        challenge() {

                        // TODO: check hash is not h2f type
                        using h2f_type =
                            hashes::h2f<Field,
                                        hash_type,
                                        hashes::h2f_default_params<Field,
                                                                   hash_type,
                                                                   128,
                                                                   hashes::UniformityCount::nonuniform_count,
                                                                   hashes::ExpandMsgVariant::rfc_xmd>>;

                        typename h2f_type::digest_type result = hash<h2f_type>(state);
                        nil::marshalling::status_type status;
                        std::vector<std::uint8_t> byte_data =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(result[0], status);
                        BOOST_ASSERT(status == nil::marshalling::status_type::success);

                        std::size_t count = std::min(byte_data.size(), state.size());
                        std::copy(byte_data.end() - count, byte_data.end(), state.begin());
                        return result[0];
                    }

                    template<typename Integral>
                    Integral int_challenge() {
                        state = hash<hash_type>(state);
                        nil::marshalling::status_type status;
                        boost::multiprecision::number<modular_backend_of_hash_size> raw_result =
                            nil::marshalling::pack(state, status);
                        // If we remove the next line, raw_result is a much larger number, conversion to 'Integral' will
                        // overflow and in debug mode an assert will fire. In release mode nothing will change.
                        raw_result &= ~Integral(0);
                        return static_cast<Integral>(raw_result);
                    }

                    template<typename Field, std::size_t N>
                    // typename std::enable_if<(Hash::digest_bits >= Field::modulus_bits),
                    //                         std::array<typename Field::value_type, N>>::type
                    std::array<typename Field::value_type, N> challenges() {

                        std::array<typename Field::value_type, N> result;
                        for (auto &ch : result) {
                            ch = challenge<Field>();
                        }

                        return result;
                    }

                private:
                    typename hash_type::digest_type state;
                };

                // Specialize for Nil Posseidon.
                template<typename Hash>
                struct fiat_shamir_heuristic_sequential<
                    Hash,
                    typename std::enable_if_t<
                        nil::crypto3::hashes::is_specialization_of<nil::crypto3::hashes::poseidon, Hash>::value>> {
                    //   After refactoring an attempt to remove this Nil Poseidon specialization was made.
                    // The difference between challenge() for other hashes and for Nil Poseidon is
                    // how the second challenge is produced. For the first call things are the same:
                    // we feed the result A (aka state in current code) of hash from operator() to hash, it
                    // puts A to sponge_state[1] (read about nil_poseidon_sponge, if you're wondered why not
                    // sponge_state[0]), then calls squeeze(). But for the second challenge thigs are
                    // different: other hashes feed state B to hash again (in case of Nil Poseidon state will
                    // be put to sponge_state[1]), but here we just run squeeze() (B is located in sponge_state[0]).
                    // Not to replace current hacks with new bigger ones, we'll just keep it.

                    typedef Hash hash_type;
                    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
                    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
                    using permutation_type = nil::crypto3::hashes::detail::poseidon_permutation<poseidon_policy>;
                    using state_type = typename permutation_type::state_type;

                    fiat_shamir_heuristic_sequential() {
                    }

                    template<typename InputRange>
                    fiat_shamir_heuristic_sequential(const InputRange &r) {
                        if (r.size() != 0) {
                            sponge.absorb(static_cast<typename hash_type::digest_type>(hash<hash_type>(r)));
                        }
                    }

                    template<typename InputIterator>
                    fiat_shamir_heuristic_sequential(InputIterator first, InputIterator last) {
                        sponge.absorb(hash<hash_type>(first, last));
                    }

                    void operator()(const typename hash_type::digest_type &input) {
                        sponge.absorb(input);
                    }

                    template<typename InputRange>
                    typename std::enable_if_t<!algebra::is_group_element<InputRange>::value>
                        operator()(const InputRange &r) {
                        sponge.absorb(static_cast<typename hash_type::digest_type>(hash<hash_type>(r)));
                    }

                    template<typename element>
                    typename std::enable_if_t<algebra::is_group_element<element>::value>
                        operator()(element const &data) {
                        auto affine = data.to_affine();
                        sponge.absorb(affine.X);
                        sponge.absorb(affine.Y);
                    }

                    template<typename InputIterator>
                    void operator()(InputIterator first, InputIterator last) {
                        sponge.absorb(hash<hash_type>(first, last));
                    }

                    template<typename Field>
                    typename Field::value_type challenge() {
                        typename Field::value_type result = sponge.squeeze();
                        return result;
                    }

                    template<typename Integral>
                    Integral int_challenge() {
                        auto c = challenge<field_type>();

                        typename field_type::integral_type intermediate_result =
                            static_cast<typename field_type::integral_type>(c.data);
                        Integral result = 0u;
                        Integral factor = 1u;
                        size_t bytes_to_fill = sizeof(Integral);
                        // TODO(martun): consider using export_bits here, or nil::marshalling::pack, instead of this.
                        while (intermediate_result > 0u && bytes_to_fill != 0u) {
                            auto last_byte = intermediate_result % 0x100u;
                            Integral last_byte_integral = static_cast<Integral>(last_byte);
                            result += factor * last_byte_integral;
                            factor *= 0x100u;
                            intermediate_result = intermediate_result / 0x100u;
                            bytes_to_fill -= 2;
                        }
                        return result;
                    }

                    template<typename Field, std::size_t N>
                    std::array<typename Field::value_type, N> challenges() {

                        std::array<typename Field::value_type, N> result;
                        for (auto &ch : result) {
                            ch = challenge<Field>();
                        }

                        return result;
                    }

                public:
                    hashes::detail::poseidon_sponge_construction_custom<typename Hash::policy_type> sponge;
                };

            }    // namespace transcript
        }    // namespace zk
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
