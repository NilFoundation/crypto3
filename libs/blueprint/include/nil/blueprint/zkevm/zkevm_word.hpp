//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#pragma once

#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

namespace nil {
    namespace blueprint {

        constexpr static const
            boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<257>> zkevm_modulus =
                        0x10000000000000000000000000000000000000000000000000000000000000000_cppui_modular257;

        constexpr static const boost::multiprecision::backends::modular_params<
                boost::multiprecision::backends::cpp_int_modular_backend<257>>
                    zkevm_modular_params = zkevm_modulus.backend();

        typedef boost::multiprecision::number<
            boost::multiprecision::backends::modular_adaptor<
                boost::multiprecision::backends::cpp_int_modular_backend<257>,
                boost::multiprecision::backends::modular_params_ct<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>,
                    zkevm_modular_params>>>
            zkevm_word_type;

        template<typename T>
        constexpr zkevm_word_type zwordc(const T &value) {
            return zkevm_word_type::backend_type(value.backend());
        }

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> zkevm_word_to_field_element(const zkevm_word_type &word) {
            using value_type = typename BlueprintFieldType::value_type;
            std::vector<value_type> chunks;
            constexpr const std::size_t chunk_size = 16;
            constexpr const std::size_t num_chunks = 256 / chunk_size;
            using integral_type = boost::multiprecision::number<
                boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            constexpr const integral_type mask =
                integral_type((zkevm_word_type(1) << chunk_size) - 1);
            integral_type word_copy = integral_type(word);
            for (std::size_t i = 0; i < num_chunks; ++i) {
                chunks.push_back(word_copy & mask);
                word_copy >>= chunk_size;
            }
            return chunks;
        }

        template<typename BlueprintFieldType>
        std::vector<typename BlueprintFieldType::value_type> chunk_64_to_16(
            const typename BlueprintFieldType::value_type &value
        ) {
            using value_type = typename BlueprintFieldType::value_type;
            using integral_type = typename BlueprintFieldType::integral_type;
            std::vector<value_type> chunks;
            constexpr const std::size_t chunk_size = 16;
            constexpr const std::size_t num_chunks = 4;
            constexpr const integral_type mask = (integral_type(1) << chunk_size) - 1;
            integral_type value_copy = integral_type(value.data);
            for (std::size_t i = 0; i < num_chunks; ++i) {
                chunks.push_back(static_cast<value_type>(value_copy & mask));
                value_copy >>= chunk_size;
            }
            return chunks;
        }

        std::uint8_t char_to_hex(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        }

        zkevm_word_type zkevm_word_from_string(std::string val){
            zkevm_word_type result;
            for(std::size_t i = 0; i < val.size(); i++ ){
                result *= 16;
                result += char_to_hex(val[i]);
            }
            return result;
        }

        template <typename BlueprintFieldType>
        typename BlueprintFieldType::value_type w_hi(const zkevm_word_type &val){
            using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

            integral_type mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000_cppui_modular257;
            return (integral_type(val) & mask) >> 128;
        }

        template <typename BlueprintFieldType>
        typename BlueprintFieldType::value_type w_lo(const zkevm_word_type &val){
            using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

            integral_type mask = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular257;
            return integral_type(val) & mask;
        }

        std::array<std::uint8_t, 32> w_to_8(const zkevm_word_type &val){
            using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

            std::array<std::uint8_t, 32> result;
            integral_type tmp(val);
            for(std::size_t i = 0; i < 32; i++){
                result[31-i] = std::uint8_t(tmp & 0xFF); tmp >>=  8;
            }
            return result;
        }

        template <typename BlueprintFieldType>
        std::array<typename BlueprintFieldType::value_type, 2> w_to_128(const zkevm_word_type &val){
            std::array<typename BlueprintFieldType::value_type, 2> result;
            result[0] = w_hi;
            result[1] = w_lo;
            return result;
        }

        // Return a/b, a%b
        std::pair<zkevm_word_type, zkevm_word_type> eth_div(const zkevm_word_type &a, const zkevm_word_type &b){
            using integral_type = boost::multiprecision::number < boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            integral_type r_integral = b != 0u ? integral_type(a) / integral_type(b) : 0u;
            zkevm_word_type r = zkevm_word_type::backend_type(r_integral.backend());
            zkevm_word_type q = b != 0u ? a % b : 0;
            return {r, q};
        }

        bool is_negative(zkevm_word_type x){
            using integral_type = boost::multiprecision::number < boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            return (integral_type(x) > zkevm_modulus/2 - 1);
        }

        zkevm_word_type negate_word(zkevm_word_type x){
            using integral_type = boost::multiprecision::number < boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            return zkevm_word_type(zkevm_modulus - integral_type(x));
        }

        zkevm_word_type abs_word(zkevm_word_type x){
            using integral_type = boost::multiprecision::number < boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            return is_negative(x)? negate_word(x) : x;
        }

        // Return a/b, a%b
        std::pair<zkevm_word_type, zkevm_word_type> eth_signed_div(const zkevm_word_type &a, const zkevm_word_type &b_input){
            using integral_type = boost::multiprecision::number < boost::multiprecision::backends::cpp_int_modular_backend<257>>;

            zkevm_word_type b = (integral_type(a) == zkevm_modulus - 1) && (integral_type(b_input) == zkevm_modulus/2) ? 1 : b_input;
            zkevm_word_type a_abs = abs_word(a),
                        b_abs = abs_word(b);

            integral_type r_integral = (b != 0u)? integral_type(a_abs) / integral_type(b_abs) : 0u;
            zkevm_word_type r_abs = zkevm_word_type::backend_type(r_integral.backend()),
                        q_abs = b != 0u ? a_abs % b_abs : a_abs,
                        r = (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs),
                        q = is_negative(a)? negate_word(q_abs) : q_abs;

            zkevm_word_type q_out = b != 0u ? q : 0; // according to EVM spec a % 0 = 0

            return {r, q_out};
        }
    }   // namespace blueprint
}   // namespace nil
