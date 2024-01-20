
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
            using filled_lookup_table_definition = typename nil::crypto3::zk::snark::filled_lookup_table_definition<BlueprintFieldType>;

            class binary_xor_table_type : public lookup_table_definition{
            public:
                binary_xor_table_type(): lookup_table_definition("binary_xor_table"){
                    this->subtables["full"] = {{0,1,2}, 0, 3};
                }
                virtual void generate(){
                    this->_table = {
                        {0, 0, 1, 1},
                        {0, 1, 0, 1},
                        {0, 1, 1, 0}
                    };
                }
                virtual std::size_t get_columns_number(){ return 3; }
                virtual std::size_t get_rows_number(){ return 4; }
            };

            class binary_and_table_type : public lookup_table_definition{
            public:
                binary_and_table_type(): lookup_table_definition("binary_and_table"){
                    this->subtables["full"] = {{0,1,2}, 0, 3};
                }
                virtual void generate(){
                    this->_table = {
                        {0, 0, 1, 1},
                        {0, 1, 0, 1},
                        {0, 0, 0, 1}
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
                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(16384);
                        i++
                    ) {
                        std::vector<bool> value(14);
                        for (std::size_t j = 0; j < 14; j++) {
                            value[14 - j - 1] = crypto3::multiprecision::bit_test(i, j);
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
                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(16384);
                        i++) {
                        std::vector<bool> value(14);
                        for (std::size_t j = 0; j < 14; j++) {
                            value[14 - j - 1] = crypto3::multiprecision::bit_test(i, j);
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
                    this->subtables["full"] = {{0,1}, 0, 65534};
                    this->subtables["first_column"] = {{0}, 0, 65534};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};
                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(65535);
                        i++
                    ) {
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                            value = components::detail::reversed_sparse_and_split_maj<BlueprintFieldType>(i, value_sizes, 4);
                        this->_table[0].push_back(value[0][0]);
                        this->_table[1].push_back(value[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 65535;}
            };

            class ch_function_table: public lookup_table_definition{
            public:
                ch_function_table(): lookup_table_definition("sha256_ch"){
                    this->subtables["full"] = {{0,1}, 0, 5765040};
                    this->subtables["first_column"] = {{0}, 0, 5765040};
                };
                virtual void generate(){
                    this->_table.resize(2);
                    std::vector<std::size_t> value_sizes = {8};
                    for (typename BlueprintFieldType::integral_type i = 0;
                        i < typename BlueprintFieldType::integral_type(5765041);
                        i++
                    ) {
                        std::array<std::vector<typename BlueprintFieldType::integral_type>, 2>
                            value = components::detail::reversed_sparse_and_split_ch<BlueprintFieldType>(i, value_sizes, 7);
                        this->_table[0].push_back(value[0][0]);
                        this->_table[1].push_back(value[1][0]);
                    }
                }

                virtual std::size_t get_columns_number(){return 2;}
                virtual std::size_t get_rows_number(){return 5765041;}
            };
        public:
            using bimap_type = boost::bimap<boost::bimaps::set_of<std::string>, boost::bimaps::set_of<std::size_t>>;
            using left_reserved_type = typename bimap_type::left_map;
            using right_reserved_type = typename bimap_type::right_map;

            lookup_library(){
                tables = {};
                reserved_all = false;
                tables["binary_xor_table"] = std::shared_ptr<lookup_table_definition>(new binary_xor_table_type());
                tables["binary_and_table"] = std::shared_ptr<lookup_table_definition>(new binary_and_table_type());
                tables["sha256_sparse_base4"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base4_table());
                tables["sha256_reverse_sparse_base4"] = std::shared_ptr<lookup_table_definition>(new reverse_sparse_sigmas_base4_table());
                tables["sha256_sparse_base7"] = std::shared_ptr<lookup_table_definition>(new sparse_values_base7_table());
                tables["sha256_reverse_sparse_base7"] = std::shared_ptr<lookup_table_definition>(new reverse_sparse_sigmas_base7_table());
                tables["sha256_maj"] = std::shared_ptr<lookup_table_definition>(new maj_function_table());
                tables["sha256_ch"] = std::shared_ptr<lookup_table_definition>(new ch_function_table());
            }

            void register_lookup_table(std::shared_ptr<lookup_table_definition> table){
                tables[table->table_name] = table;
            }

            void reserve_table(std::string name){
                BOOST_ASSERT(!reserved_all);
                std::string table_name = name.substr(0, name.find("/"));
                BOOST_ASSERT(tables.find(table_name) != tables.end());
                std::string subtable_name = name.substr(name.find("/")+1, name.size());
                BOOST_ASSERT(tables[table_name]->subtables.find(subtable_name) != tables[table_name]->subtables.end());
                reserved_tables.insert(name);
                reserved_tables_indices.left.insert(std::make_pair(name, reserved_tables.size()));
            }

            void reservation_done() const {
                if(reserved_all) return;

                reserved_all = true;
                for (auto &name : reserved_tables){
                    auto slash_pos = name.find("/");
                    std::string table_name = name.substr(0, slash_pos);
                    BOOST_ASSERT(tables.find(table_name) != tables.end());
                    std::string subtable_name = name.substr(slash_pos + 1, name.size());
                    auto const &table = tables.at(table_name);
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

            const bimap_type &get_reserved_indices() const {
                return reserved_tables_indices;
            }

            const std::map<std::string, std::shared_ptr<lookup_table_definition>> &get_reserved_tables() const {
                reservation_done();
                return reserved_tables_map;
            }
        protected:
            mutable bool reserved_all;

            std::map<std::string, std::shared_ptr<lookup_table_definition>> tables;
            std::set<std::string> reserved_tables;
            bimap_type reserved_tables_indices;
            mutable std::map<std::string, std::shared_ptr<lookup_table_definition>> reserved_tables_map;
        };
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_LOOKUP_TABLE_HPP