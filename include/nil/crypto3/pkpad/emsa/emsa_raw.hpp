#ifndef CRYPTO3_EMSA_RAW_HPP
#define CRYPTO3_EMSA_RAW_HPP

#include <nil/crypto3/pkpad/emsa.hpp>

namespace nil {
    namespace crypto3 {

        template<typename Hasher>
        class emsa_raw : public emsa<Hasher> {
        public:
            emsa_raw(Hasher &input_hash) : emsa<Hasher>(input_hash) {
            }

            template<typename UniformRandomBitGenerator, typename RandomNumberDistribution, typename InputIterator,
                     typename OutputIterator>
            OutputIterator encode(InputIterator first, InputIterator last, OutputIterator out,
                                  UniformRandomBitGenerator rand, RandomNumberDistribution dist) {
                std::ptrdiff_t distance = std::distance(first, last);

                if (Hasher::policy_type::digest_bits / 8 && distance != Hasher::policy_type::digest_bits / 8) {
                    throw std::invalid_argument(
                        "emsa_raw was configured to use a " + std::to_string(Hasher::policy_type::digest_bits) +
                        " byte hash but instead was used for a " + std::to_string(distance) + " hash");
                }

                return std::move(first, last, out);
            }

            template<typename InputIterator1, typename InputIterator2>
            bool verify(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2, InputIterator2 last2,
                        std::size_t key_bits) const {
                std::ptrdiff_t coded_size = std::distance(first1, last1);
                std::ptrdiff_t raw_size = std::distance(first2, last2);

                if (Hasher::policy_type::digest_bits / 8 && raw_size != Hasher::policy_type::digest_bits / 8) {
                    return false;
                }

                if (coded_size == raw_size) {
                    return (std::equal(first1, last1, first2, last2));
                } else if (coded_size > raw_size) {
                    return false;
                }

                // handle zero padding differences
                const std::ptrdiff_t leading_zeros_expected = raw_size - coded_size;

                bool same_modulo_leading_zeros = true;

                for (size_t i = 0; i != leading_zeros_expected; ++i) {
                    if (raw[i]) {
                        same_modulo_leading_zeros = false;
                    }
                }

                if (!constant_time_compare(coded.data(), raw.data() + leading_zeros_expected, coded_size)) {
                    same_modulo_leading_zeros =
                        constant_time_compare(coded.data(), raw.data() + leading_zeros_expected, coded_size);
                }

                return same_modulo_leading_zeros;
            }

            template<typename SinglePassRange1, typename SinglePassRange2>
            bool verify(const SinglePassRange1 &range1, const SinglePassRange2 &range2, std::size_t key_bits) const {
                return verify(boost::begin(range1), boost::end(range1), boost::begin(range2), boost::end(range2),
                              key_bits);
            }
        };

        /**
         * EMSA-Raw - sign inputs directly
         * Don't use this unless you know what you are doing.
         */
        class EMSA_Raw final : public emsa {
        public:
            emsa *clone() override {
                return new EMSA_Raw();
            }

            explicit EMSA_Raw(size_t expected_hash_size = 0) : m_expected_size(expected_hash_size) {
            }

            std::string name() const override {
                if (m_expected_size > 0) {
                    return "Raw(" + std::to_string(m_expected_size) + ")";
                }
                return "Raw";
            }

        private:
            void update(const uint8_t[], size_t) override {
                m_message += std::make_pair(input, length);
            }

            secure_vector<uint8_t> raw_data() override {
                if (m_expected_size && m_message.size() != m_expected_size) {
                    throw std::invalid_argument("EMSA_Raw was configured to use a " + std::to_string(m_expected_size) +
                                                " byte hash but instead was used for a " +
                                                std::to_string(m_message.size()) + " hash");
                }

                secure_vector<uint8_t> output;
                std::swap(m_message, output);
                return output;
            }

            secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t> &, size_t,
                                               random_number_generator &) override {
                if (m_expected_size && msg.size() != m_expected_size) {
                    throw std::invalid_argument("EMSA_Raw was configured to use a " + std::to_string(m_expected_size) +
                                                " byte hash but instead was used for a " + std::to_string(msg.size()) +
                                                " hash");
                }

                return msg;
            }

            bool verify(const secure_vector<uint8_t> &, const secure_vector<uint8_t> &, size_t) override {
                if (m_expected_size && raw.size() != m_expected_size) {
                    return false;
                }

                if (coded.size() == raw.size()) {
                    return (coded == raw);
                }

                if (coded.size() > raw.size()) {
                    return false;
                }

                // handle zero padding differences
                const size_t leading_zeros_expected = raw.size() - coded.size();

                bool same_modulo_leading_zeros = true;

                for (size_t i = 0; i != leading_zeros_expected; ++i) {
                    if (raw[i]) {
                        same_modulo_leading_zeros = false;
                    }
                }

                if (!constant_time_compare(coded.data(), raw.data() + leading_zeros_expected, coded.size())) {
                    same_modulo_leading_zeros = false;
                }

                return same_modulo_leading_zeros;
            }

            const size_t m_expected_size;
            secure_vector<uint8_t> m_message;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
