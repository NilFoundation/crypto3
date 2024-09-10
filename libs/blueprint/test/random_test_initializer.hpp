//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_TEST_TOOLS_RANDOM_TEST_INITIALIZER_HPP
#define CRYPTO3_ZK_TEST_TOOLS_RANDOM_TEST_INITIALIZER_HPP

#include <boost/test/unit_test.hpp>
#include <regex>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>


namespace nil {
    namespace test_tools {

        // *******************************************************************************
        // * Randomness setup
        // *******************************************************************************/
        // Template structure to include algebraic random engines for multiple field types
        template<typename... FieldTypes>
        struct random_engine_container {
            std::size_t seed;
            std::tuple<nil::crypto3::random::algebraic_engine<FieldTypes>...> alg_rnd_engines;

            explicit random_engine_container(std::size_t init_seed = 0)
                : alg_rnd_engines(nil::crypto3::random::algebraic_engine<FieldTypes>(init_seed)...) {
            }

            // Template method to access a specific engine by type
            template<typename FieldType>
            nil::crypto3::random::algebraic_engine<FieldType>& get_alg_engine() {
                return std::get<nil::crypto3::random::algebraic_engine<FieldType>>(alg_rnd_engines);
            }
        };

        template<typename... FieldType>
        struct random_test_initializer {
            random_test_initializer() {
                for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc - 1); i++) {
                    if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                        if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                            std::random_device rd;
                            seed = rd();
                            break;
                        }
                        if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                            std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                            seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                            break;
                        }
                    }
                }

                BOOST_TEST_MESSAGE("seed = " << seed);
                alg_random_engines = random_engine_container<FieldType...>(seed);
                generic_random_engine = boost::random::mt11213b(seed);
            }

            std::size_t seed = 0;
            random_engine_container<FieldType...> alg_random_engines;
            boost::random::mt11213b generic_random_engine;
        };

    }    // namespace test_tools
}    // namespace nil

#endif    // CRYPTO3_ZK_TEST_TOOLS_RANDOM_TEST_INITIALIZER_HPP
