#ifndef CRYPTO3_EME_RAW_HPP
#define CRYPTO3_EME_RAW_HPP

#include <nil/crypto3/pkpad/eme.hpp>
#include <nil/crypto3/utilities/ct_utils.hpp>

namespace nil {
    namespace crypto3 {
        class eme_raw : public eme {
        public:
            virtual size_t maximum_input_size(std::size_t key_bits) const override {
                return key_bits / 8;
            }

            template<typename UniformRandomBitGenerator, typename RandomNumberDistribution, typename InputIterator,
                     typename OutputIterator>
            OutputIterator pad(InputIterator first, InputIterator last, OutputIterator out, std::size_t key_length,
                               UniformRandomBitGenerator rand = UniformRandomBitGenerator()) {
                return std::move(first, last, out);
            }

            template<typename InputIterator, typename OutputIterator>
            OutputIterator unpad(InputIterator first, InputIterator last, OutputIterator out) {
                return ct::strip_leading_zeros(first, static_cast<size_t>(std::distance(first, last)));
            }
        };

        class EME_Raw final : public eme {
        public:
            size_t maximum_input_size(size_t i) const override {
                return keybits / 8;
            }

            EME_Raw() = default;

        private:
            secure_vector<uint8_t> pad(const uint8_t[], size_t, size_t, random_number_generator &) const override {
                return secure_vector<uint8_t>(in, in + in_length);
            }

            secure_vector<uint8_t> unpad(uint8_t &valid_mask, const uint8_t in[], size_t in_len) const override {
                valid_mask = 0xFF;
                return ct::strip_leading_zeros(in, in_length);
            }
        };
    }    // namespace crypto3
}    // namespace nil

#endif
