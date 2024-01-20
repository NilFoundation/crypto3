//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <optional>
#include <iostream>
#include <fstream>
#include <sstream>

#include <nil/blueprint/detail/lookup_table_precomputes.hpp>

#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                template<typename Iterator, typename BlueprintFieldType>
                struct value_vector_parser : boost::spirit::qi::grammar<Iterator,
                        std::vector<typename BlueprintFieldType::value_type>(),
                        boost::spirit::qi::ascii::space_type> {
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using return_type = std::vector<value_type>;

                    value_vector_parser(std::size_t size) : value_vector_parser::base_type(start) {
                        using boost::spirit::qi::uint_parser;
                        using boost::spirit::qi::_val;
                        using boost::spirit::qi::_1;
                        using boost::spirit::qi::_2;
                        using boost::spirit::qi::repeat;
                        using boost::phoenix::construct;
                        using boost::phoenix::val;
                        auto number = uint_parser<integral_type, 16, 1,
                                                  (BlueprintFieldType::modulus_bits + 16 - 1) / 16>();
                        start = repeat(size)[number];

                        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
                            start,
                            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
                        );
                    }

                    boost::spirit::qi::rule<Iterator, return_type(), boost::spirit::qi::ascii::space_type> start;
                };

                template <typename BlueprintFieldType>
                bool parse_lookup_table(
                        std::istream &ist,
                        const std::size_t line_size,
                        std::vector<std::vector<typename BlueprintFieldType::value_type>> &result) {
                    using value_type = typename BlueprintFieldType::value_type;
                    std::string line;
                    // Get the table size
                    std::getline(ist, line);
                    std::size_t table_size = std::stoull(line);
                    result.resize(line_size);
                    for (auto &column : result) {
                        column.resize(table_size);
                    }
                    for (std::size_t i = 0; i < table_size; i++) {
                        std::getline(ist, line);
                        std::vector<value_type> row;
                        value_vector_parser<decltype(line.begin()), BlueprintFieldType> parser(line_size);
                        boost::spirit::qi::ascii::space_type space;
                        bool parsing_result =
                            boost::spirit::qi::phrase_parse(line.begin(), line.end(), parser, space, row);
                        if (!parsing_result) {
                            return false;
                        }
                        for (std::size_t j = 0; j < line_size; j++) {
                            result[j][i] = row[j];
                        }
                    }
                    return true;
                }

                // Loads the table from file, trying multiple different filen paths if one fails
                template <typename BlueprintFieldType>
                bool load_lookup_table(
                        const std::set<std::string> &candidate_file_paths,
                        const std::size_t line_size,
                        std::vector<std::vector<typename BlueprintFieldType::value_type>> &result) {

                    for (const auto &path : candidate_file_paths) {
                        // try opening the file
                        std::ifstream file(path);
                        if (!file.is_open()) {
                            continue;
                        }
                        auto status = parse_lookup_table<BlueprintFieldType>(file, line_size, result);
                        if (status) {
                            return true;
                        }
                    }
                    return false;
                }

                // This forcefully includes the table in the binary
                // It's not in binary form here because for current tables the ASCII form is actually smaller
                // due to the advanced compression stratgy of "we don't have to write leading zeroes"
                template <typename BlueprintFieldType>
                bool load_lookup_table_from_bin(
                    std::string table_name,
                    std::vector<std::vector<typename BlueprintFieldType::value_type>> &result) {

                    if (table_name == "8_split_4") {
                        const std::string table_data = _8_SPLIT_4;
                        std::stringstream ss(table_data);
                        return parse_lookup_table<BlueprintFieldType>(ss, 2, result);
                    } else if (table_name == "8_split_7") {
                        const std::string table_data = _8_SPLIT_7;
                        std::stringstream ss(table_data);
                        return parse_lookup_table<BlueprintFieldType>(ss, 2, result);
                    } else {
                        return false;
                    }
                }
            }   // namespace detail
        }       // namespace components
    }           // namespace blueprint
}    // namespace nil
