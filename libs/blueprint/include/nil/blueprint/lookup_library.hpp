
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Tatuzova Elena <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_LOOKUP_LIBRARY_HPP
#define CRYPTO3_LOOKUP_LIBRARY_HPP

#include <string>
#include <map>

#include <boost/bimap.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/blueprint/detail/lookup_table_loaders.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/assert.hpp>

namespace nil {
    namespace blueprint {
        template <typename Type, typename = void>
        struct component_use_lookup : std::false_type{ };

        template <typename Type>
        struct component_use_lookup<Type,
            typename std::enable_if<std::is_member_function_pointer<decltype(&Type::component_lookup_tables)>::value>::type> : std::true_type
        { };

        template <typename Type>
        constexpr bool use_lookups(){
            if(component_use_lookup<Type>::value){
                return true;
            }
            return false;
        }

        template <typename Type, typename = void>
        struct component_use_custom_lookup_tables : std::false_type{ };

        template <typename Type>
        struct component_use_custom_lookup_tables<Type,
            typename std::enable_if<std::is_member_function_pointer<decltype(&Type::component_custom_lookup_tables)>::value>::type> : std::true_type
        { };

        template <typename BlueprintFieldType>
        class lookup_library {
            using lookup_table_definition = typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;
            using dynamic_table_definition = typename nil::crypto3::zk::snark::dynamic_table_definition<BlueprintFieldType>;
            using filled_lookup_table_definition = typename nil::crypto3::zk::snark::filled_lookup_table_definition<BlueprintFieldType>;

            class byte_range_table_type: public lookup_table_definition{
            public:
                using lookup_table_definition = typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                byte_range_table_type(): lookup_table_definition("byte_range_table"){
                    this->subtables["full"] = {{0}, 0, 255};
                }
                virtual void generate(){
                    this->_table.push_back({});
                    for( std::size_t i = 0; i < 256; i++){
                        this->_table[0].push_back({i});
                    }
                }
                virtual std::size_t get_columns_number(){ return 1; }
                virtual std::size_t get_rows_number(){ return 256; }
            };

            class zkevm_opcode_table: public lookup_table_definition{
            public:
                static constexpr std::size_t opcodes_num = 149;

                zkevm_opcode_table(): lookup_table_definition("zkevm_opcodes"){
                    this->subtables["full"] = {{0, 1, 2}, 0, opcodes_num};
                    this->subtables["opcodes_only"] = {{0}, 0, opcodes_num};
                }
                virtual void generate(){
                    // opcodes
                    this->_table.push_back({
                        0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,   0x9,  0xa,  0xb,                              //12
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,                 //14
                        0x20,                                                                                               //1
                        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,     //16
                        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,                                   //11
                        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,     //16
                        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,     //16
                        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,     //16
                        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,     //16
                        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,     //16
                        0xa0, 0xa1, 0xa2, 0xa3, 0xa4,                                                                       //5
                        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,                         0xfa,             0xfd, 0xfe, 0xff      //10
                    });
                    // push_size
                    this->_table.push_back({
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,                              //12
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,                  //14
                        0x0,                                                                                                //1
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,      //16
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,                                    //11
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,      //16
                        0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0x10,     //16
                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,     //16
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,     //16
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,     //16
                        0x0,  0x0,  0x0,  0x0,  0x0,                                                                       //5
                        0x0,  0x0,  0x0,  0x0,  0x0,  0x0,                          0x0,              0x0,  0x0,  0x0      //10
                    });

                    this->_table.push_back({});
                    for( std::size_t i = 0; i < opcodes_num; i++) this->_table[2].push_back(1);

                    // unselected rows virtualization
                    this->_table[0].push_back(0);
                    this->_table[1].push_back(0);
                    this->_table[2].push_back(0);
                }
                virtual std::size_t get_columns_number(){ return 1; }
                virtual std::size_t get_rows_number(){ return 256; }
            };

            class binary_xor_table_type : public lookup_table_definition{
            public:
                binary_xor_table_type(): lookup_table_definition("binary_xor_table"){
                    this->subtables["full"] = {{0,1,2}, 0, 3};
                }
                virtual void generate(){
                    this->_table = {
                        {0u, 0u, 1u, 1u},
                        {0u, 1u, 0u, 1u},
                        {0u, 1u, 1u, 0u}
                    };
                }
                virtual std::size_t get_columns_number(){ return 3; }
                virtual std::size_t get_rows_number(){ return 4; }
            };

            class keccak_pack_table_type : public lookup_table_definition{
                typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    integral_type value_integral = integral_type(value.data);
                    integral_type result_integral = 0;
                    integral_type power = 1;
                    for (int i = 0; i < 64; ++i) {
                        integral_type bit = value_integral & 1;
                        result_integral = result_integral + bit * power;
                        value_integral = value_integral >> 1;
                        power = power << 3;
                    }
                    return value_type(result_integral);
                }
            public:
                keccak_pack_table_type(): lookup_table_definition("keccak_pack_table"){
                    this->subtables["full"] = {{0,1}, 0, 255};
                    this->subtables["range_check"] = {{0}, 0, 255};
                    this->subtables["range_check_sparse"] = {{1}, 0, 255};
                    this->subtables["range_check_135"] = {{0}, 0, 135};
                    this->subtables["extended"] = {{0,1}, 0, 65535};
                    this->subtables["range_check_16bit"] = {{0}, 0, 65535};
                    this->subtables["sparse_16bit"] = {{1}, 0, 65535};
                    this->subtables["extended_swap"] = {{2,1}, 0, 65535};
                }
                virtual void generate(){
                    this->_table.resize(3);

                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(65536);
                        i++
                    ) {
                        this->_table[0].push_back(i);
                        this->_table[1].push_back(to_sparse(i));
                        this->_table[2].push_back(typename BlueprintFieldType::value_type((
                            ((i & typename BlueprintFieldType::integral_type(0xFF)) << 8) +
                            ((i & typename BlueprintFieldType::integral_type(0xFF00)) >> 8)
                        )));
                    }
                }
                virtual std::size_t get_columns_number(){ return 3; }
                virtual std::size_t get_rows_number(){ return 256; }
            };
        protected:

            class binary_and_table_type : public lookup_table_definition{
            public:
                binary_and_table_type(): lookup_table_definition("binary_and_table"){
                    this->subtables["full"] = {{0,1,2}, 0, 3};
                }
                virtual void generate(){
                    this->_table = {
                        {0u, 0u, 1u, 1u},
                        {0u, 1u, 0u, 1u},
                        {0u, 0u, 0u, 1u}
                    };
                }
                virtual std::size_t get_columns_number(){ return 3; }
                virtual std::size_t get_rows_number(){ return 4; }
            };

            class sparse_values_base4_table: public lookup_table_definition {
            public:
                sparse_values_base4_table(): lookup_table_definition("sha256_sparse_base4"){
                    this->subtables["full"] = {{0,1}, 0, 16383};
                    this->subtables["first_column"] = {{0}, 0, 16383};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {14};

                    // lookup table for sparse values with base = 4
                    for (typename BlueprintFieldType::integral_type i = 0u;
                        i < typename BlueprintFieldType::integral_type(16384u);
                        i++
                    ) {
                        std::vector<bool> value(14);
                        for (std::size_t j = 0; j < 14; j++) {
                            value[14 - j - 1] = boost::multiprecision::bit_test(i, j);
                        }
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> value_chunks =
                            components::detail::split_and_sparse<BlueprintFieldType>(value, value_sizes, 4);
                        this->_table[0].push_back(value_chunks[0][0]);
                        this->_table[1].push_back(value_chunks[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 16384;}
            };

            class reverse_sparse_sigmas_base4_table : public lookup_table_definition {
            public:
                reverse_sparse_sigmas_base4_table(): lookup_table_definition("sha256_reverse_sparse_base4"){
                    this->subtables["full"] = {{0,1}, 0, 65535};
                };

                virtual void generate() {
                    bool status = components::detail::load_lookup_table_from_bin<BlueprintFieldType>(
                        "8_split_4",
                        this->_table);
                    if (!status) {
                        std::cerr << "Failed to load table 8_split_4 from binary!" << std::endl;
                        BLUEPRINT_RELEASE_ASSERT(0);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 65536;}
            };

            class sparse_values_base7_table: public lookup_table_definition{
            public:
                sparse_values_base7_table(): lookup_table_definition("sha256_sparse_base7"){
                    this->subtables["full"] = {{0,1}, 0, 16383};
                    this->subtables["first_column"] = {{0}, 0, 16383};
                    this->subtables["second_column"] = {{1}, 0, 16383};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {14};
                    for (typename BlueprintFieldType::integral_type i = 0u;
                        i < typename BlueprintFieldType::integral_type(16384u);
                        i++) {
                        std::vector<bool> value(14);
                        for (std::size_t j = 0; j < 14; j++) {
                            value[14 - j - 1] = boost::multiprecision::bit_test(i, j);
                        }
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> value_chunks =
                            components::detail::split_and_sparse<BlueprintFieldType>(value, value_sizes, 7);
                        this->_table[0].push_back(value_chunks[0][0]);
                        this->_table[1].push_back(value_chunks[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 16384;}
            };

            class reverse_sparse_sigmas_base7_table: public lookup_table_definition{
            public:
                reverse_sparse_sigmas_base7_table(): lookup_table_definition("sha256_reverse_sparse_base7"){
                    this->subtables["full"] = {{0,1}, 0, 43903};
                };
                virtual void generate() {
                    bool status = components::detail::load_lookup_table_from_bin<BlueprintFieldType>(
                        "8_split_7",
                        this->_table);
                    if (!status) {
                        std::cerr << "Failed to load table 8_split_7 from binary!" << std::endl;
                        BLUEPRINT_RELEASE_ASSERT(0);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 43904;}
            };

            class maj_function_table: public lookup_table_definition{
            public:
                maj_function_table(): lookup_table_definition("sha256_maj"){
                    this->subtables["full"] = {{0,1}, 0, 65535};
                    this->subtables["first_column"] = {{0}, 0, 65535};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};
                    for (typename BlueprintFieldType::integral_type i = 0u;
                        i < typename BlueprintFieldType::integral_type(65536u);
                        i++
                    ) {
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                            value = components::detail::reversed_sparse_and_split_maj<BlueprintFieldType>(i, value_sizes, 4);
                        this->_table[0].push_back(value[0][0]);
                        this->_table[1].push_back(value[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 65536;}
            };

            class ch_function_table: public lookup_table_definition{
            public:
                ch_function_table(): lookup_table_definition("sha256_ch"){
                    this->subtables["full"] = {{0,1}, 0, 5764800};
                    this->subtables["first_column"] = {{0}, 0, 5764800};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};
                    for (typename BlueprintFieldType::integral_type i = 0u;
                        i < typename BlueprintFieldType::integral_type(5764801u);
                        i++
                    ) {
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                            value = components::detail::reversed_sparse_and_split_ch<BlueprintFieldType>(i, value_sizes, 7);
                        this->_table[0].push_back(value[0][0]);
                        this->_table[1].push_back(value[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 5764801;}
            };

            class sparse_values_base8_table : public lookup_table_definition{
                typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    integral_type value_integral = integral_type(value.data);
                    integral_type result_integral = 0;
                    integral_type power = 1;
                    for (int i = 0; i < 64; ++i) {
                        integral_type bit = value_integral & 1;
                        result_integral = result_integral + bit * power;
                        value_integral = value_integral >> 1;
                        power = power << 3;
                    }
                    return value_type(result_integral);
                }
            public:
                sparse_values_base8_table(): lookup_table_definition("keccak_pack_table"){
                    this->subtables["full"] = {{0,1}, 0, 255};
                    this->subtables["range_check"] = {{0}, 0, 255};
                    this->subtables["range_check_sparse"] = {{1}, 0, 255};
                    this->subtables["64bit"] = {{0}, 128, 255};
                }
                virtual void generate(){
                    this->_table.resize(2);

                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(256);
                        i++
                    ) {
                        this->_table[0].push_back(i);
                        this->_table[1].push_back(to_sparse(i));
                    }
                }
                virtual std::size_t get_columns_number(){ return 2; }
                virtual std::size_t get_rows_number(){ return 256; }
            };

            class sparse_values_base8_sign_bit_table : public lookup_table_definition{
                // "keccak_pack_table/64bit" doesn't work, so we need to use this temporary table
                typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    integral_type value_integral = integral_type(value.data);
                    integral_type result_integral = 0;
                    integral_type power = 1;
                    for (int i = 0; i < 64; ++i) {
                        integral_type bit = value_integral & 1;
                        result_integral = result_integral + bit * power;
                        value_integral = value_integral >> 1;
                        power = power << 3;
                    }
                    return value_type(result_integral);
                }
            public:
                sparse_values_base8_sign_bit_table(): lookup_table_definition("keccak_sign_bit_table"){
                    this->subtables["full"] = {{0}, 0, 128};
                }
                virtual void generate(){
                    this->_table.resize(2);
                    this->_table[0].push_back(0);
                    this->_table[1].push_back(0);
                    for (typename BlueprintFieldType::integral_type i = 128;
                        i < typename BlueprintFieldType::integral_type(256);
                        i++
                    ) {
                        this->_table[0].push_back(i);
                        this->_table[1].push_back(to_sparse(i));
                    }
                }
                virtual std::size_t get_columns_number(){ return 1; }
                virtual std::size_t get_rows_number(){ return 129; }
            };

            class normalize_base8_table_type : public lookup_table_definition{
                std::size_t base;
                virtual std::array<typename BlueprintFieldType::integral_type, 2> to_base(std::size_t base, typename BlueprintFieldType::integral_type num) {
                    typename BlueprintFieldType::integral_type result = 0;
                    typename BlueprintFieldType::integral_type normalized_result = 0;
                    typename BlueprintFieldType::integral_type power = 1;
                    while (num > 0) {
                        result = result + (num % base)*power;
                        normalized_result = normalized_result  + ((num % base) & 1)*power;
                        num /= base;
                        power <<= 3;
                    }
                    return {result, normalized_result};
                }
            public:
                normalize_base8_table_type(std::size_t base_)
                    : lookup_table_definition("keccak_normalize" + std::to_string(base_) + "_table"), base(base_) {

                    this->subtables["full"] = {{0,1}, 0, 65535};
                }

                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};

                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(65536);
                        i++
                    ) {
                        std::array<typename BlueprintFieldType::integral_type, 2> value = to_base(base, i);
                        this->_table[0].push_back(value[0]);
                        this->_table[1].push_back(value[1]);
                    }
                }
                virtual std::size_t get_columns_number(){ return 2; }
                virtual std::size_t get_rows_number(){ return 65536; }
            };

            class chi_table_type : public lookup_table_definition{
                virtual std::array<typename BlueprintFieldType::integral_type, 2> to_base_chi(typename BlueprintFieldType::integral_type num) {
                    std::size_t base = 5;
                    typename BlueprintFieldType::integral_type table[5] = {0, 1, 1, 0, 0};
                    typename BlueprintFieldType::integral_type result = 0;
                    typename BlueprintFieldType::integral_type chi_result = 0;
                    typename BlueprintFieldType::integral_type power = 1;
                    while (num > 0) {
                        result = result + (num % base) * power;
                        chi_result = chi_result + table[int(num % base)] * power;
                        num /= base;
                        power <<= 3;
                    }
                    return {result, chi_result};
                }
            public:
                chi_table_type(): lookup_table_definition("keccak_chi_table") {
                    this->subtables["full"] = {{0,1}, 0, 65535};
                }
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};

                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(65536);
                        i++
                    ) {
                        std::array<typename BlueprintFieldType::integral_type, 2> value = to_base_chi(i);
                        this->_table[0].push_back(value[0]);
                        this->_table[1].push_back(value[1]);
                    }
                }
                virtual std::size_t get_columns_number(){ return 2; }
                virtual std::size_t get_rows_number(){ return 65536; }
            };

            class chunk_16_bits_table: public lookup_table_definition{
            public:
                chunk_16_bits_table(): lookup_table_definition("chunk_16_bits"){
                    this->subtables["full"] = {{0}, 0, 65535};
                    this->subtables["8bits"] = {{0}, 0, 255};
                    this->subtables["10bits"] = {{0}, 0, 1023};
                };
                virtual void generate(){
                    this->_table.resize(1);
                    for (std::size_t i = 0; i < 65536; i++) {
                        this->_table[0].push_back(i);
                    }
                }

                virtual std::size_t get_columns_number(){return 1;}
                virtual std::size_t get_rows_number(){return 65536;}
            };

            class byte_and_xor_table_type : public lookup_table_definition{
            public:
                byte_and_xor_table_type(): lookup_table_definition("byte_and_xor_table"){
                    this->subtables["full"] = {{0,1,2,3}, 0, 65535};
                    this->subtables["and"] = {{0,1,2}, 0, 65535};
                    this->subtables["xor"] = {{0,1,3}, 0, 65535};
                    this->subtables["word"] = {{0,1}, 0, 65535};
                }
                virtual void generate(){
                    this->_table.resize(4);
                    for(std::size_t x = 0; x < 256; x++) {
                        for(std::size_t y = 0; y < 256; y++) {
                            this->_table[0].push_back(x);
                            this->_table[1].push_back(y);
                            this->_table[2].push_back(x & y);
                            this->_table[3].push_back(x ^ y);
                        }
                    }
                }
                virtual std::size_t get_columns_number(){ return 4; }
                virtual std::size_t get_rows_number(){ return 65536; }
            };

        public:
            using bimap_type = boost::bimap<boost::bimaps::set_of<std::string>, boost::bimaps::set_of<std::size_t>>;
            using left_reserved_type = typename bimap_type::left_map;
            using right_reserved_type = typename bimap_type::right_map;

            lookup_library() {
                tables = {};
                reserved_all = false;
                tables["chunk_16_bits"] = std::shared_ptr<lookup_table_definition>(new chunk_16_bits_table());
                tables["binary_xor_table"] = std::shared_ptr<lookup_table_definition>(new binary_xor_table_type());
                tables["binary_and_table"] = std::shared_ptr<lookup_table_definition>(new binary_and_table_type());
                tables["sha256_sparse_base4"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base4_table());
                tables["sha256_reverse_sparse_base4"] = std::shared_ptr<lookup_table_definition>(new reverse_sparse_sigmas_base4_table());
                tables["sha256_sparse_base7"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base7_table());
                tables["sha256_reverse_sparse_base7"] = std::shared_ptr<lookup_table_definition>(new reverse_sparse_sigmas_base7_table());
                tables["sha256_maj"] = std::shared_ptr<lookup_table_definition>(new maj_function_table());
                tables["sha256_ch"] = std::shared_ptr<lookup_table_definition>(new ch_function_table());
                tables["keccak_pack_table"] = std::shared_ptr<lookup_table_definition>(new keccak_pack_table_type());
//                tables["keccak_pack_table"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base8_table());
                tables["keccak_sign_bit_table"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base8_sign_bit_table());
                tables["keccak_normalize3_table"] = std::shared_ptr<lookup_table_definition>(new normalize_base8_table_type(3));
                tables["keccak_normalize4_table"] = std::shared_ptr<lookup_table_definition>(new normalize_base8_table_type(4));
                tables["keccak_normalize6_table"] = std::shared_ptr<lookup_table_definition>(new normalize_base8_table_type(6));
                tables["keccak_chi_table"] = std::shared_ptr<lookup_table_definition>(new chi_table_type());
                tables["byte_range_table"] = std::shared_ptr<lookup_table_definition>(new byte_range_table_type());
                tables["zkevm_opcodes"] = std::shared_ptr<lookup_table_definition>(new zkevm_opcode_table());
                tables["byte_and_xor_table"] = std::shared_ptr<lookup_table_definition>(new byte_and_xor_table_type());
            }

            void register_lookup_table(std::shared_ptr<lookup_table_definition> table){
                tables[table->table_name] = table;
            }

            void register_dynamic_table(std::string table_name){
                BOOST_ASSERT(tables.find(table_name) == tables.end());
                dynamic_tables[table_name] = std::shared_ptr<dynamic_table_definition>(new dynamic_table_definition(table_name));
            }

            void reserve_table(std::string name){
                BOOST_ASSERT(!reserved_all);
                std::string table_name = name.substr(0, name.find("/"));
                // Necessary for dynamic and for fixed tables
                BOOST_ASSERT(tables.find(table_name) != tables.end());
                std::string subtable_name = name.substr(name.find("/")+1, name.size());
                BOOST_ASSERT(tables[table_name]->subtables.find(subtable_name) != tables[table_name]->subtables.end());
                reserved_tables.insert(name);
                reserved_tables_indices.left.insert(std::make_pair(name, reserved_tables.size()));
            }

            void reserve_dynamic_table(std::string name){
                BOOST_ASSERT(tables.find(name) == tables.end());
                BOOST_ASSERT(!reserved_all);

                register_dynamic_table(name);
                reserved_tables.insert(name);
                reserved_tables_indices.left.insert(std::make_pair(name, reserved_tables.size()));
            }

            void define_dynamic_table(std::string table_name, const crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> &lookup_table){
                register_dynamic_table(table_name);
                auto table = dynamic_tables[table_name];
                BOOST_ASSERT(!table->is_defined());
                table->define(lookup_table);
                BOOST_ASSERT(table->is_defined());
            }

            std::shared_ptr<dynamic_table_definition> get_dynamic_table_definition(std::string table_name){
                auto table = dynamic_tables[table_name];
                BOOST_ASSERT(table->is_defined());
                return std::shared_ptr<dynamic_table_definition>(table);
            }

            void reservation_done() const {
                if(reserved_all) return;

                reserved_all = true;
                for (auto &name : reserved_tables){
                    if( dynamic_tables.find(name) != dynamic_tables.end() ){
                        reserved_dynamic_tables_map[name] = dynamic_tables.at(name);
                    } else {
                        auto slash_pos = name.find("/");
                        std::string table_name = name.substr(0, slash_pos);
                        BOOST_ASSERT(tables.find(table_name) != tables.end());
                        auto const &table = tables.at(table_name);

                        std::string subtable_name = name.substr(slash_pos + 1, name.size());
                        BOOST_ASSERT(table->subtables.find(subtable_name) !=
                                    table->subtables.end());

                        if( reserved_tables_map.find(table_name) == reserved_tables_map.end() ){
                            filled_lookup_table_definition *filled_definition =
                                new filled_lookup_table_definition(*(table));
                            reserved_tables_map[table_name] = std::shared_ptr<lookup_table_definition>(filled_definition);
                        }
                        reserved_tables_map[table_name]->subtables[subtable_name] =
                            table->subtables[subtable_name];
                    }
                }
            }

            const bimap_type &get_reserved_indices() const {
                return reserved_tables_indices;
            }

            const std::map<std::string, std::shared_ptr<lookup_table_definition>> &get_reserved_tables() const {
                reservation_done();
                return reserved_tables_map;
            }

            const std::map<std::string, std::shared_ptr<dynamic_table_definition>> &get_reserved_dynamic_tables() const {
                reservation_done();
                return reserved_dynamic_tables_map;
            }
        protected:
            mutable bool reserved_all;

            std::set<std::string> reserved_tables;
            bimap_type reserved_tables_indices;
            std::map<std::string, std::shared_ptr<lookup_table_definition>> tables;
            mutable std::map<std::string, std::shared_ptr<lookup_table_definition>> reserved_tables_map;
            std::map<std::string, std::shared_ptr<dynamic_table_definition>> dynamic_tables;
            mutable std::map<std::string, std::shared_ptr<dynamic_table_definition>> reserved_dynamic_tables_map;
        };
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_LOOKUP_TABLE_HPP
