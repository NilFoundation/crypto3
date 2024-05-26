//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

#include <nil/crypto3/zk/blueprint/r1cs.hpp>
#include <nil/crypto3/zk/blueprint/detail/r1cs/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/disjunction.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/verification_key.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;

template<typename FieldType>
components::blueprint<FieldType> test_disjunction_component(size_t w) {
    
    using field_type = FieldType;

    std::size_t n = std::log2(w) + 
        ((w > (1ul << std::size_t(std::log2(w))))? 1 : 0);

    components::blueprint<field_type> bp;
    components::blueprint_variable<field_type> output;
    output.allocate(bp);

    bp.set_input_sizes(1);

    components::blueprint_variable_vector<field_type> inputs;
    inputs.allocate(bp, n);

    components::disjunction<field_type> d(bp, inputs, output);
    d.generate_r1cs_constraints();

    for (std::size_t j = 0; j < n; ++j) {
        bp.val(inputs[j]) = typename field_type::value_type((w & (1ul << j)) ? 1 : 0);
    }

    d.generate_r1cs_witness();

    assert(bp.val(output) == (w ? field_type::value_type::one() : field_type::value_type::zero()));
    assert(bp.is_satisfied());

    return bp;
}

int main(int argc, char *argv[]) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    using Endianness = nil::marshalling::option::big_endian;

    typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;

    std::size_t num_constraints = 1000, input_size = 100;

    boost::filesystem::path pout, pkout, vkout, piout, viout;
    boost::program_options::options_description options(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("generate", "Generate proofs and/or keys")
    ("verify", "verify proofs and/or keys")
    ("proof-output,po", boost::program_options::value<boost::filesystem::path>(&pout)->default_value("proof"))
    ("primary-input-output,pio", boost::program_options::value<boost::filesystem::path>(&piout)->default_value
("pinput"))
    ("proving-key-output,pko", boost::program_options::value<boost::filesystem::path>(&pkout)->default_value("pkey"))
    ("verifying-key-output,vko", boost::program_options::value<boost::filesystem::path>(&vkout)->default_value("vkey"))
    ("verifier-input-output,vio", boost::program_options::value<boost::filesystem::path>(&viout)->default_value("vio"));
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    std::cout << "Blueprint generation started." << std::endl;

    components::blueprint<scalar_field_type> bp = test_disjunction_component<scalar_field_type>(10);

    std::cout << "Blueprint generation finished." << std::endl;

    std::cout << "R1CS generation started." << std::endl;

    std::cout << "R1CS generation finished." << std::endl;

    std::cout << "Starting generator" << std::endl;

    typename scheme_type::keypair_type keypair = zk::snark::generate<scheme_type>(bp.get_constraint_system());

    std::cout << "Starting prover" << std::endl;

    const typename scheme_type::proof_type proof =
        zk::snark::prove<scheme_type>(keypair.first, bp.primary_input(), bp.auxiliary_input());
    
    using verification_key_marshalling_type = types::r1cs_gg_ppzksnark_verification_key<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::verification_key_type>;

    verification_key_marshalling_type filled_verification_key_val = 
        types::fill_r1cs_gg_ppzksnark_verification_key<
            typename scheme_type::verification_key_type,
            Endianness>(keypair.second);

    using proof_marshalling_type = types::r1cs_gg_ppzksnark_proof<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::proof_type>;

    proof_marshalling_type filled_proof_val = 
        types::fill_r1cs_gg_ppzksnark_proof<
            typename scheme_type::proof_type,
            Endianness>(proof);

    using primary_input_marshalling_type = types::r1cs_gg_ppzksnark_primary_input<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::primary_input_type>;

    primary_input_marshalling_type filled_primary_input_val = 
        types::fill_r1cs_gg_ppzksnark_primary_input<
            typename scheme_type::primary_input_type,
            Endianness>(bp.primary_input());

    std::cout << "Marshalling types filled." << std::endl;

    using unit_type = unsigned char;

    std::vector<unit_type> verification_key_byteblob;
    verification_key_byteblob.resize(filled_verification_key_val.length(), 0x00);
    auto write_iter = verification_key_byteblob.begin();

    typename nil::marshalling::status_type status =  
        filled_verification_key_val.write(write_iter, 
            verification_key_byteblob.size());

    std::vector<unit_type> proof_byteblob;
    proof_byteblob.resize(filled_proof_val.length(), 0x00);
    write_iter = proof_byteblob.begin();

    status = filled_proof_val.write(write_iter, 
            proof_byteblob.size());

    std::vector<unit_type> primary_input_byteblob;

    primary_input_byteblob.resize(filled_primary_input_val.length(), 0x00);
    auto primary_input_write_iter = primary_input_byteblob.begin();

    status = filled_primary_input_val.write(primary_input_write_iter, 
            primary_input_byteblob.size());

    std::cout << "Byteblobs filled." << std::endl;

    if (vm.count("verifying-key-output")) {
        boost::filesystem::ofstream out(vkout);
        for (const auto &v : verification_key_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("proof-output")) {
        boost::filesystem::ofstream out(pout);
        for (const auto &v : proof_byteblob) {
            out << v;
        }
        out.close();
    }

    if (vm.count("primary-input-output")) {
        boost::filesystem::ofstream out(piout);
        for (const auto &v : primary_input_byteblob) {
            out << v;
        }
        out.close();
    }

    // nil::marshalling::status_type provingProcessingStatus = nil::marshalling::status_type::success;
    // typename scheme_type::proving_key_type other =
    //             nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proving_key_process(
    //                 proving_key_byteblob.cbegin(),
    //                 proving_key_byteblob.cend(),
    //                 provingProcessingStatus);

    // assert(keypair.first == other);

    if (vm.count("verifier-input-output")) {
        std::vector<std::uint8_t> verifier_input_output_byteblob(proof_byteblob.begin(), proof_byteblob.end());

        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), primary_input_byteblob.begin(),
                                              primary_input_byteblob.end());
        verifier_input_output_byteblob.insert(verifier_input_output_byteblob.end(), verification_key_byteblob.begin(),
                                              verification_key_byteblob.end());

        boost::filesystem::ofstream poutf(viout);
        for (const auto &v : verifier_input_output_byteblob) {
            poutf << v;
        }
        poutf.close();
    }

    return 0;
}