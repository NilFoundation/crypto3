//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_common_data_test

#include <boost/test/included/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include "./detail/circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;


bool has_argv(std::string name){
    bool result = false;
    for (std::size_t i = 0; i < std::size_t(boost::unit_test::framework::master_test_suite().argc); i++) {
        if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--print") {
            result = true;
        }
    }
    return result;
}

template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
}

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const std::size_t max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename CommonDataType>
void test_placeholder_common_data(CommonDataType common_data, std::string folder_name = "") {
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_common_data = nil::crypto3::marshalling::types::fill_placeholder_common_data<Endianness, CommonDataType>(common_data);
    auto _common_data = nil::crypto3::marshalling::types::make_placeholder_common_data<Endianness,CommonDataType>(filled_common_data);
    BOOST_CHECK(common_data == _common_data);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_common_data.length(), 0x00);
    auto write_iter = cv.begin();
    auto status = filled_common_data.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, CommonDataType> test_val_read;
    auto read_iter = cv.begin();
    test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    auto constructed_val_read = nil::crypto3::marshalling::types::make_placeholder_common_data<Endianness, CommonDataType>(
            test_val_read
    );
    BOOST_CHECK(common_data == constructed_val_read);
    if(folder_name != "") {
        std::filesystem::create_directory(folder_name);
        std::ofstream out;
        out.open(folder_name + "/common.dat");
        out << "0x";
        print_hex_byteblob(out, cv.begin(), cv.end(), false);
        out.close();
        std::cout << "common data saved to '" << folder_name << "'" << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE(placeholder_circuit1_poseidon)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

    using merkle_hash_type = poseidon_type;
    using transcript_hash_type = poseidon_type;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_AUTO_TEST_CASE(common_data_marshalling_test) {
    auto circuit = circuit_test_1<field_type>();

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data, "circuit1");
    else
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    using merkle_hash_type = hashes::keccak_1600<256>;
    using transcript_hash_type = hashes::keccak_1600<256>;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_AUTO_TEST_CASE(common_data_marshalling_test) {
    auto circuit = circuit_test_1<field_type>();

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};


    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data, "circuit1");
    else
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data, "circuit2");
    else
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_3<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data, "circuit3");
    else
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_4<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data, "circuit4");
    else
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };

    using circuit_t_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data, "circuit5");
    else
        test_placeholder_common_data<common_data_type>(lpc_preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_6<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data, "circuit6");
    else
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(common_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_7<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        circuit.table.witnesses().size(),
        circuit.table.public_inputs().size(),
        circuit.table.constants().size(),
        circuit.table.selectors().size(),
        circuit.usable_rows,
        circuit.table_rows);

    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using common_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;
    if(has_argv("--print"))
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data, "circuit7");
    else
        test_placeholder_common_data<common_data_type>(preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

template<
    typename curve_type,
    typename transcript_hash_type,
    bool UseGrinding = false>
struct placeholder_kzg_test_fixture_v2 : public test_tools::random_test_initializer<typename curve_type::scalar_field_type> {
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme_v2<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
        circuit_description<field_type,
        placeholder_circuit_params<field_type> >;

    placeholder_kzg_test_fixture_v2(circuit_type const& circuit_in)
        : circuit(circuit_in),
        desc(circuit_in.table.witnesses().size(),
                circuit_in.table.public_inputs().size(),
                circuit_in.table.constants().size(),
                circuit_in.table.selectors().size(),
                circuit_in.usable_rows,
                circuit_in.table_rows)
    {
    }

    bool run_test() {
        std::size_t table_rows_log = std::log2(circuit.table_rows);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

        // KZG commitment scheme
        typename kzg_type::field_type::value_type alpha(7u);
        auto kzg_params = kzg_scheme_type::create_params(1 << table_rows_log, alpha);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_public_data =
            placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, kzg_scheme, columns_with_copy_constraints.size()
            );

        using common_data_type = typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type::common_data_type;
            using Endianness = nil::marshalling::option::big_endian;
        using TTypeBase = nil::marshalling::field_type<Endianness>;
        nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, common_data_type> filled_data;

        if(has_argv("--print"))
            test_placeholder_common_data<common_data_type>(kzg_preprocessed_public_data.common_data, std::string("circuit_") + typeid(curve_type).name());
        else
            test_placeholder_common_data<common_data_type>(kzg_preprocessed_public_data.common_data);

        return true;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
};


BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg_v2)

    using TestFixtures = boost::mpl::list<
    placeholder_kzg_test_fixture_v2< algebra::curves::bls12_381, hashes::keccak_1600<256>, true>,
    placeholder_kzg_test_fixture_v2< algebra::curves::mnt4_298, hashes::keccak_1600<256>, true>,
    placeholder_kzg_test_fixture_v2< algebra::curves::mnt6_298, hashes::keccak_1600<256>, true>
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(common_data_marshalling_test, F, TestFixtures) {
    using field_type = typename F::field_type;
    test_tools::random_test_initializer<field_type> random_test_initializer;
    typename field_type::value_type pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    F fixture(circuit);
    BOOST_CHECK(fixture.run_test());
}

BOOST_AUTO_TEST_SUITE_END()
