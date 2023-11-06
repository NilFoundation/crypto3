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


#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

#include <array>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <unordered_set>

#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                // Works only for small-ish powers
                template <typename BlueprintFieldType, std::size_t Power>
                struct SumHash {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    std::size_t operator()(const std::pair<integral_type, integral_type> &a) const {
                        return std::size_t((a.first << Power) + a.second);
                    }
                };

                template <typename BlueprintFieldType>
                void print_sha_table_to_stream(
                        const std::unordered_set<std::pair<
                            typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                            SumHash<BlueprintFieldType, 15>> &input,
                        std::ostream &stream) {
                    using value_type = typename BlueprintFieldType::value_type;
                    using Endianness = nil::marshalling::option::big_endian;
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using marshalling_value_type = nil::crypto3::marshalling::types::field_element<TTypeBase, value_type>;
                    stream << input.size() << std::endl;
                    for (const auto &[preimage, image] : input) {
                        std::vector<marshalling_value_type> pair = {
                            marshalling_value_type(preimage),
                            marshalling_value_type(image)};
                        stream << std::hex << pair[0].value() << " " << std::hex << pair[1].value() << std::endl;
                    }
                }

                template <typename BlueprintFieldType>
                void base4_reverse_table_iter(
                    std::unordered_set<std::pair<
                        typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                        SumHash<BlueprintFieldType, 15>> &output_set,
                    const typename BlueprintFieldType::integral_type &i,
                    const std::size_t table_size,
                    std::mutex &set_guard) {

                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    static const std::vector<std::size_t> a_sizes = {3, 4, 11, 14};
                    static const std::vector<std::size_t> b_sizes = {10, 7, 2, 13};
                    static const std::vector<std::size_t> c_sizes = {2, 11, 9, 10};
                    static const std::vector<std::size_t> sigma_sizes = {8, 8, 8, 8};
                    static const integral_type one = 1;
                    static const std::array<integral_type, 4> a_mult = {
                        (one << 50) + (1 << 28),
                        1 + (one << 56) + (one << 34),
                        (1 << 8) + 1 + (one << 42),
                        (1 << 30) + (1 << 22) + 1,
                    };
                    static const std::array<integral_type, 4> b_mult = {
                        (1 << 30) + (1 << 26),
                        1 + (one << 50) + (one << 46),
                        (1 << 14) + 1 + (one << 60),
                        (1 << 18) + (1 << 4) + 1
                    };
                    static const std::array<integral_type, 4> sigma_mult = {
                        (one << 38) + (1 << 20) + (one << 60),
                        (one << 42) + 1 + (1 << 24),
                        (1 << 22) + (one << 46) + 1,
                        (one << 40) + (1 << 18) + 1
                    };
                    static const std::size_t base4 = 4;
                    static const value_type base4_value = value_type(base4);

                    std::vector<bool> value(table_size);
                    for (std::size_t j = 0; j < table_size; j++) {
                        value[table_size - j - 1] = crypto3::multiprecision::bit_test(i, j);
                    }
                    // s0
                    const std::array<std::vector<integral_type>, 2> a_chunks =
                        nil::blueprint::components::detail::split_and_sparse<BlueprintFieldType>(value, a_sizes, base4);
                    integral_type sparse_sigma0 =
                        a_chunks[1][1] * a_mult[1] +
                        a_chunks[1][2] * a_mult[2] +
                        a_chunks[1][3] * a_mult[3] +
                        a_chunks[1][0] * a_mult[0];
                    const std::array<std::vector<integral_type>, 2> sigma0_chunks =
                        nil::blueprint::components::detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_sigma0, sigma_sizes, base4);
                    // s1
                    const std::array<std::vector<integral_type>, 2> b_chunks =
                        nil::blueprint::components::detail::split_and_sparse<BlueprintFieldType>(value, b_sizes, base4);

                    integral_type sparse_sigma1 =
                        b_chunks[1][1] * b_mult[1] +
                        b_chunks[1][2] * b_mult[2] +
                        b_chunks[1][3] * b_mult[3] +
                        b_chunks[1][0] * b_mult[0];

                    const std::array<std::vector<integral_type>, 2> sigma1_chunks =
                        nil::blueprint::components::detail::reversed_sparse_and_split<BlueprintFieldType>(sparse_sigma1, sigma_sizes, base4);
                    // S0
                    const std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> c_chunks =
                        nil::blueprint::components::detail::split_and_sparse<BlueprintFieldType>(
                            value, c_sizes, base4);
                    integral_type sparse_Sigma0 =
                        c_chunks[1][0] * sigma_mult[0] +
                        c_chunks[1][1] * sigma_mult[1] +
                        c_chunks[1][2] * sigma_mult[2] +
                        c_chunks[1][3] * sigma_mult[3];
                    std::array<std::vector<integral_type>, 2> Sigma0_chunks =
                        nil::blueprint::components::detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_Sigma0, sigma_sizes, base4);
                    {
                        std::scoped_lock<std::mutex> lock(set_guard);

                        output_set.insert(std::make_pair(sigma0_chunks[0][0], sigma0_chunks[1][0]));
                        output_set.insert(std::make_pair(sigma0_chunks[0][1], sigma0_chunks[1][1]));
                        output_set.insert(std::make_pair(sigma0_chunks[0][2], sigma0_chunks[1][2]));
                        output_set.insert(std::make_pair(sigma0_chunks[0][3], sigma0_chunks[1][3]));

                        output_set.insert(std::make_pair(sigma1_chunks[0][0], sigma1_chunks[1][0]));
                        output_set.insert(std::make_pair(sigma1_chunks[0][1], sigma1_chunks[1][1]));
                        output_set.insert(std::make_pair(sigma1_chunks[0][2], sigma1_chunks[1][2]));
                        output_set.insert(std::make_pair(sigma1_chunks[0][3], sigma1_chunks[1][3]));

                        output_set.insert(std::make_pair(Sigma0_chunks[0][0], Sigma0_chunks[1][0]));
                        output_set.insert(std::make_pair(Sigma0_chunks[0][1], Sigma0_chunks[1][1]));
                        output_set.insert(std::make_pair(Sigma0_chunks[0][2], Sigma0_chunks[1][2]));
                        output_set.insert(std::make_pair(Sigma0_chunks[0][3], Sigma0_chunks[1][3]));
                    }
                }

                template <typename BlueprintFieldType>
                void base4_reverse_table_worker(
                    std::unordered_set<std::pair<
                            typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                            SumHash<BlueprintFieldType, 15>> &output_set,
                    typename BlueprintFieldType::integral_type start,
                    typename BlueprintFieldType::integral_type end,
                    const std::size_t table_size,
                    std::mutex &set_guard) {

                    using integral_type = typename BlueprintFieldType::integral_type;
                    for (integral_type i = start; i < end; i++) {
                        base4_reverse_table_iter<BlueprintFieldType>(output_set, i, table_size, set_guard);
                    }
                }

                template <typename BlueprintFieldType, std::size_t ThreadNum>
                void generate_base4_reverse_table(
                        std::unordered_set<std::pair<
                            typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                            SumHash<BlueprintFieldType, 15>> &output_set,
                        const std::size_t table_size) {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    const integral_type one = 1;
                    auto start = std::chrono::high_resolution_clock::now();
                    std::mutex set_guard;
                    std::array<std::thread, ThreadNum> threads;
                    // Dispatching does not work otherwise
                    static_assert(ThreadNum == 1 || ThreadNum % 2 == 0 && ThreadNum > 1);
                    // Filling the cache
                    // We have to do this, because cache modification is not thread safe
                    base4_reverse_table_worker<BlueprintFieldType>(
                        std::ref(output_set),
                        0,
                        1,
                        table_size,
                        std::ref(set_guard));
                    for (std::size_t i = 0; i < ThreadNum; i++) {
                        threads[i] = std::thread(
                            base4_reverse_table_worker<BlueprintFieldType>,
                            std::ref(output_set),
                            (integral_type(one << table_size) / ThreadNum) * i,
                            (integral_type(one << table_size) / ThreadNum) * (i + 1),
                            table_size,
                            std::ref(set_guard));
                    }
                    for (std::size_t i = 0; i < ThreadNum; i++) {
                        threads[i].join();
                    }
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::high_resolution_clock::now() - start);
                    std::cerr << "Time elapsed: " << duration.count() << " seconds" << std::endl;
                    std::cerr << "Total size: " << std::dec << output_set.size() << std::endl;
                }

                template <typename BlueprintFieldType>
                void base7_reverse_table_iter(
                    std::unordered_set<std::pair<
                        typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                        SumHash<BlueprintFieldType, 15>> &output_set,
                    const typename BlueprintFieldType::integral_type &i,
                    const std::size_t table_size,
                    std::mutex &set_guard) {

                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    static const std::vector<std::size_t> e_sizes = {6, 5, 14, 7};
                    static const std::vector<std::size_t> sigma_sizes = {8, 8, 8, 8};
                    static const integral_type one = 1;
                    static const std::size_t base7 = 7;
                    static const value_type base7_value = value_type(base7);
                    static const std::array<integral_type, 4> e_mult = {
                        integral_type((base7_value.pow(26) + base7_value.pow(21) + base7_value.pow(7)).data),
                        integral_type((base7_value.pow(27) + base7_value.pow(13) + 1).data),
                        integral_type((base7_value.pow(5) + base7_value.pow(18) + 1).data),
                        integral_type((base7_value.pow(19) + base7_value.pow(14) + 1).data)
                    };

                    std::vector<bool> value(table_size);
                    for (std::size_t j = 0; j < table_size; j++) {
                        value[table_size - j - 1] = crypto3::multiprecision::bit_test(i, j);
                    }

                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> e_chunks =
                        nil::blueprint::components::detail::split_and_sparse<BlueprintFieldType>(
                            value, e_sizes, base7);

                    integral_type sparse_Sigma1 =
                        e_chunks[1][1] * e_mult[1] +
                        e_chunks[1][2] * e_mult[2] +
                        e_chunks[1][3] * e_mult[3] +
                        e_chunks[1][0] * e_mult[0];
                    std::array<std::vector<typename BlueprintFieldType::integral_type>, 2> Sigma1_chunks =
                        nil::blueprint::components::detail::reversed_sparse_and_split<BlueprintFieldType>(
                            sparse_Sigma1, sigma_sizes, base7);
                    {
                        std::scoped_lock<std::mutex> lock(set_guard);

                        output_set.insert(std::make_pair(Sigma1_chunks[0][0], Sigma1_chunks[1][0]));
                        output_set.insert(std::make_pair(Sigma1_chunks[0][1], Sigma1_chunks[1][1]));
                        output_set.insert(std::make_pair(Sigma1_chunks[0][2], Sigma1_chunks[1][2]));
                        output_set.insert(std::make_pair(Sigma1_chunks[0][3], Sigma1_chunks[1][3]));
                    }
                }

                template <typename BlueprintFieldType>
                void base7_reverse_table_worker(
                    std::unordered_set<std::pair<
                            typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                            SumHash<BlueprintFieldType, 15>> &output_set,
                    typename BlueprintFieldType::integral_type start,
                    typename BlueprintFieldType::integral_type end,
                    const std::size_t table_size,
                    std::mutex &set_guard) {

                    using integral_type = typename BlueprintFieldType::integral_type;
                    for (integral_type i = start; i < end; i++) {
                        base7_reverse_table_iter<BlueprintFieldType>(output_set, i, table_size, set_guard);
                    }
                }

                template <typename BlueprintFieldType, std::size_t ThreadNum>
                void generate_base7_reverse_table(
                        std::unordered_set<std::pair<
                            typename BlueprintFieldType::integral_type, typename BlueprintFieldType::integral_type>,
                            SumHash<BlueprintFieldType, 15>> &output_set,
                        const std::size_t table_size) {
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using value_type = typename BlueprintFieldType::value_type;

                    const integral_type one = 1;

                    auto start = std::chrono::high_resolution_clock::now();
                    std::mutex set_guard;
                    std::array<std::thread, ThreadNum> threads;

                    // Dispatching does not work otherwise
                    static_assert(ThreadNum == 1 || ThreadNum % 2 == 0 && ThreadNum > 1);
                    // Filling the cache
                    // We have to do this, because cache modification is not thread safe
                    base7_reverse_table_worker<BlueprintFieldType>(
                        std::ref(output_set),
                        0,
                        1,
                        table_size,
                        std::ref(set_guard));
                    for (std::size_t i = 0; i < ThreadNum; i++) {
                        threads[i] = std::thread(
                            base7_reverse_table_worker<BlueprintFieldType>,
                            std::ref(output_set),
                            (integral_type(one << table_size) / ThreadNum) * i,
                            (integral_type(one << table_size) / ThreadNum) * (i + 1),
                            table_size,
                            std::ref(set_guard));
                    }
                    for (std::size_t i = 0; i < ThreadNum; i++) {
                        threads[i].join();
                    }
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::high_resolution_clock::now() - start);
                    std::cerr << "Time elapsed: " << duration.count() << " seconds" << std::endl;
                    std::cerr << "Total size: " << std::dec << output_set.size() << std::endl;
                }

                template<typename Iterator, typename BlueprintFieldType>
                struct value_pair_parser : boost::spirit::qi::grammar<Iterator,
                        std::pair<typename BlueprintFieldType::value_type,
                                  typename BlueprintFieldType::value_type>(),
                        boost::spirit::qi::ascii::space_type> {
                    using value_type = typename BlueprintFieldType::value_type;
                    using integral_type = typename BlueprintFieldType::integral_type;
                    using return_type = std::pair<value_type, value_type>;

                    value_pair_parser() : value_pair_parser::base_type(start) {
                        using boost::spirit::qi::uint_parser;
                        using boost::spirit::qi::_val;
                        using boost::spirit::qi::_1;
                        using boost::spirit::qi::_2;
                        using boost::phoenix::construct;
                        using boost::phoenix::val;
                        auto nubmer = uint_parser<integral_type, 16, 1,
                                                  (BlueprintFieldType::modulus_bits + 16 - 1) / 16>();
                        start = (nubmer >> nubmer)
                                [_val = construct<std::pair<value_type, value_type>>(_1, _2)];

                        boost::spirit::qi::on_error<boost::spirit::qi::fail>(
                            start,
                            std::cerr << val("Error! Expecting ") << boost::spirit::qi::_4 << val(" here: \"")
                                      << construct<std::string>(boost::spirit::_3, boost::spirit::_2) << val("\"\n")
                        );
                    }

                    boost::spirit::qi::rule<Iterator, return_type(), boost::spirit::qi::ascii::space_type> start;
                };

                // Loads the table from file, trying multiple different filen paths if one fails
                template <typename BlueprintFieldType>
                std::vector<std::vector<typename BlueprintFieldType::value_type>> load_sha_table(
                        const std::set<std::string> &candidate_file_paths) {
                    using value_type = typename BlueprintFieldType::value_type;
                    std::vector<std::vector<value_type>> result;
                    result.resize(2);
                    for (const auto &path : candidate_file_paths) {
                        // try opening the file
                        std::ifstream file(path);
                        if (!file.is_open()) {
                            continue;
                        }
                        std::string line;
                        // Get the table size
                        std::getline(file, line);
                        std::size_t table_size = std::stoull(line);
                        result[0].resize(table_size);
                        result[1].resize(table_size);
                        bool parsing_failed = false;
                        for (std::size_t i = 0; i < table_size; i++) {
                            std::getline(file, line);
                            std::pair<value_type, value_type> pair;
                            value_pair_parser<decltype(line.begin()), BlueprintFieldType> parser;
                            boost::spirit::qi::ascii::space_type space;
                            bool parsing_result =
                                boost::spirit::qi::phrase_parse(line.begin(), line.end(), parser, space, pair);
                            if (!parsing_result) {
                                std::cerr << "Failed to parse file " << path << " as table, retrying..." << std::endl;
                                parsing_failed = true;
                                break;
                            }
                            result[0][i] = pair.first;
                            result[1][i] = pair.second;
                        }
                        if (!parsing_failed) {
                            return result;
                        }
                    }
                    // if all the attempts failed, return empty vector
                    result.resize(0);
                    return result;
                }

            }   // namespace detail
        }       // namespace components
    }           // namespace blueprint
}    // namespace nil