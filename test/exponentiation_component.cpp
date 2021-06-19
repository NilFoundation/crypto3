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

#define BOOST_TEST_MODULE exponentiation_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/components/algebra/fields/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp4.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp6_2over3.hpp>

using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FpkT, template<class> class Fpk_variableT, template<class> class Fpk_mul_componentT,
         template<class> class Fpk_sqr_componentT>
void test_exponentiation_component(const typename FpkT::modulus_type &power) {
    typedef typename FpkT::base_field_type FieldType;

    components::blueprint<FieldType> bp;
    Fpk_variableT<FpkT> x(bp);
    Fpk_variableT<FpkT> x_to_power(bp);
    components::exponentiation_component<FpkT, Fpk_variableT, Fpk_mul_componentT, Fpk_sqr_componentT,
                             typename FpkT::modulus_type>
        exp_component(bp, x, power, x_to_power);
    exp_component.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 10; ++i) {
        const typename FpkT::value_type x_val = random_element<FpkT>();
        x.generate_r1cs_witness(x_val);
        exp_component.generate_r1cs_witness();
        const typename FpkT::value_type res = x_to_power.get_element();
        BOOST_CHECK(bp.is_satisfied());
        BOOST_CHECK(res == (x_val.pow(power)));
    }
    std::cout << "Number of constraints: " << bp.num_constraints() << std::endl;
    std::cout << "Power: " << power << std::endl;
}

BOOST_AUTO_TEST_SUITE(exponentiation_component_test_suite)

BOOST_AUTO_TEST_CASE(exponentiation_component_mnt4_298_test_case) {

    std::cout << "Testing mnt4<298>: " << std::endl;

    test_exponentiation_component<curves::mnt4<298>::pairing::fqk_type, components::element_fp4, 
        components::element_fp4_mul, components::element_fp4_squared>(
            curves::mnt4<298>::pairing::final_exponent_last_chunk_abs_of_w0);

}

BOOST_AUTO_TEST_CASE(exponentiation_component_mnt6_298_test_case) {

    std::cout << "Testing mnt6<298>: " << std::endl;

    test_exponentiation_component<curves::mnt6<298>::pairing::fqk_type, components::element_fp6_2over3, 
        components::element_fp6_2over3_mul, components::element_fp6_2over3_squared>(
            curves::mnt6<298>::pairing::final_exponent_last_chunk_abs_of_w0);
}

BOOST_AUTO_TEST_SUITE_END()
