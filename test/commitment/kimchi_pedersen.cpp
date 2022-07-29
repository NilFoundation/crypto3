#define BOOST_TEST_MODULE kimchi_commitment_test

#include <string>
#include <algorithm>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
                
BOOST_AUTO_TEST_SUITE(kimchi_commitment_test_suite)

BOOST_AUTO_TEST_CASE(kimchi_commitment_test_case){
    using curve_type = algebra::curves::vesta;
    using scalar_field_type = curve_type::scalar_field_type;
    using scalar_value_type = scalar_field_type::value_type;
    using kimchi_pedersen = commitments::kimchi_pedersen<curve_type>;
    using sponge_type = kimchi_pedersen::sponge_type;
    using params_type = kimchi_pedersen::params_type;
    using batchproof_type = kimchi_pedersen::batchproof_type;

    snark::group_map<curve_type> g_map;
    sponge_type fq_sponge;
    // std::cout << (1 << 7) << '\n';
    params_type srs = kimchi_pedersen::setup(1 << 7);

    std::vector<batchproof_type> proofs; 

    std::size_t count_eval_proofs = 7;
    for(std::size_t i = 0; i < count_eval_proofs; ++i){
        std::vector<scalar_value_type> eval_points(7);
        std::generate(eval_points.begin(), eval_points.end(), algebra::random_element<scalar_field_type>);

        
    }
}

BOOST_AUTO_TEST_SUITE_END()