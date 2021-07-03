//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#include <boost/program_options.hpp>

#include <nil/crypto3/zk/snark/default_types/ram_zksnark_pp.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/memory/examples/memory_contents_examples.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_params.hpp>
#include <nil/crypto3/zk/snark/schemes/zksnark/ram_zksnark/examples/run_ram_zksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/zksnark/ram_zksnark/ram_zksnark.hpp>

using namespace nil::crypto3::zk::snark;

template<typename FieldType>
void simulate_random_memory_contents(const tinyram_architecture_params &ap, const std::size_t input_size,
                                     const std::size_t program_size) {
    const std::size_t num_addresses = 1ul << ap.dwaddr_len();
    const std::size_t value_size = 2 * ap.w;
    memory_contents init_random =
        random_memory_contents(num_addresses, value_size, program_size + (input_size + 1) / 2);

    std::cout << "Initialize random delegated memory" << std::endl;
    delegated_ra_memory<FieldType> dm_random(num_addresses, value_size, init_random);
}

template<typename CurveType>
void profile_ram_zksnark_verifier(const tinyram_architecture_params &ap, const std::size_t input_size,
                                  const std::size_t program_size) {
    typedef ram_zksnark_machine_pp<CurveType> RAMType;
    const std::size_t time_bound = 10;

    const std::size_t boot_trace_size_bound = program_size + input_size;
    const ram_example<RAMType> example = gen_ram_example_complex<RAMType>(ap, boot_trace_size_bound, time_bound, true);

    ram_zksnark_proof<CurveType> pi;
    ram_zksnark_verification_key<CurveType> vk = ram_zksnark_verification_key<CurveType>::dummy_verification_key(ap);

    std::cout << "Verify fake proof" << std::endl;
    ram_zksnark_verifier<CurveType>(vk, example.boot_trace, time_bound, pi);
}

template<typename CurveType>
void print_ram_zksnark_verifier_profiling() {
    algebra::inhibit_profiling_info = true;
    for (std::size_t w : {16, 32}) {
        const std::size_t k = 16;

        for (std::size_t input_size : {0, 10, 100}) {
            for (std::size_t program_size = 10; program_size <= 10000; program_size *= 10) {
                const tinyram_architecture_params ap(w, k);

                profile_ram_zksnark_verifier<CurveType>(ap, input_size, program_size);

                const double input_map = algebra::last_times["Call to ram_zksnark_verifier_input_map"];
                const double preprocessing = algebra::last_times["Call to r1cs_ppzksnark_process_verification_key"];
                const double accumulate = algebra::last_times["Call to r1cs_ppzksnark_IC_query::accumulate"];
                const double pairings = algebra::last_times["Online pairing computations"];
                const double total = algebra::last_times["Call to ram_zksnark_verifier"];
                const double rest = total - (input_map + preprocessing + accumulate + pairings);

                const double delegated_ra_memory_init =
                    algebra::last_times["Construct delegated_ra_memory from memory map"];
                simulate_random_memory_contents<algebra::Fr<typename CurveType::curve_A_pp>>(ap, input_size,
                                                                                             program_size);
                const double delegated_ra_memory_init_random =
                    algebra::last_times["Initialize random delegated memory"];
                const double input_map_random = input_map - delegated_ra_memory_init + delegated_ra_memory_init_random;
                const double total_random = total - delegated_ra_memory_init + delegated_ra_memory_init_random;

                printf(
                    "w = %zu, k = %zu, program_size = %zu, input_size = %zu, input_map = %0.2fms, preprocessing = "
                    "%0.2fms, accumulate = %0.2fms, pairings = %0.2fms, rest = %0.2fms, total = %0.2fms "
                    "(input_map_random = %0.2fms, total_random = %0.2fms)\n",
                    w, k, program_size, input_size, input_map * 1e-6, preprocessing * 1e-6, accumulate * 1e-6,
                    pairings * 1e-6, rest * 1e-6, total * 1e-6, input_map_random * 1e-6, total_random * 1e-6);
            }
        }
    }
}

template<typename CurveType>
void profile_ram_zksnark(const tinyram_architecture_params &ap, const std::size_t program_size,
                         const std::size_t input_size, const std::size_t time_bound) {
    typedef ram_zksnark_machine_pp<CurveType> RAMType;

    const std::size_t boot_trace_size_bound = program_size + input_size;
    const ram_example<RAMType> example = gen_ram_example_complex<RAMType>(ap, boot_trace_size_bound, time_bound, true);
    const bool bit = run_ram_zksnark<CurveType>(example);
    assert(bit);
}

namespace po = boost::program_options;

bool process_command_line(const int argc, const char **argv, bool &profile_gp, std::size_t &w, std::size_t &k,
                          bool &profile_v, std::size_t &l) {
    try {
        po::options_description desc("Usage");
        desc.add_options()("help", "print this help message")("profile_gp", "profile generator and prover")(
            "w", po::value<std::size_t>(&w)->default_value(16), "word size")(
            "k", po::value<std::size_t>(&k)->default_value(16), "register count")("profile_v", "profile verifier")(
            "v", "print version info")("l", po::value<std::size_t>(&l)->default_value(10), "program length");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("v")) {
            algebra::print_compilation_info();
            exit(0);
        }

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return false;
        }

        profile_gp = vm.count("profile_gp");
        profile_v = vm.count("profile_v");

        if (!(vm.count("profile_gp") ^ vm.count("profile_v"))) {
            std::cout << "Must choose between profiling generator/prover and profiling verifier (see --help)\n";
            return false;
        }

        po::notify(vm);
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return false;
    }

    return true;
}

int main(int argc, const char *argv[]) {
    bool profile_gp;
    std::size_t w;
    std::size_t k;
    bool profile_v;
    std::size_t l;

    if (!process_command_line(argc, argv, profile_gp, w, k, profile_v, l)) {
        return 1;
    }

    tinyram_architecture_params ap(w, k);

    if (profile_gp) {
        profile_ram_zksnark<default_ram_zksnark_pp>(ap, 100, 100, 10);    // w, k, l, n, T
    }

    if (profile_v) {
        profile_ram_zksnark_verifier<default_ram_zksnark_pp>(ap, l / 2, l / 2);
    }
}
