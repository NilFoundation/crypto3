//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/exponentiation_component.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename FpkT, template<class> class Fpk_variableT, template<class> class Fpk_mul_componentT,
         template<class> class Fpk_sqr_componentT, typename Backend,
         boost::multiprecision::expression_template_option ExpressionTemplates>
void test_exponentiation_component(const boost::multiprecision::number<Backend, ExpressionTemplates> &power) {
    typedef typename FpkT::my_Fp FieldType;

    blueprint<FieldType> bp;
    Fpk_variableT<FpkT> x(bp);
    Fpk_variableT<FpkT> x_to_power(bp);
    exponentiation_component<FpkT, Fpk_variableT, Fpk_mul_componentT, Fpk_sqr_componentT,
                             boost::multiprecision::number<Backend, ExpressionTemplates>>
        exp_component(bp, x, power, x_to_power);
    exp_component.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 10; ++i) {
        const FpkT x_val = algebra::random_element<FpkT>();
        x.generate_r1cs_witness(x_val);
        exp_component.generate_r1cs_witness();
        const FpkT res = x_to_power.get_element();
        assert(bp.is_satisfied());
        assert(res == (x_val ^ power));
    }
    power.print();
}

BOOST_AUTO_TEST_SUITE(exponentiation_component_test_suite)

BOOST_AUTO_TEST_CASE(exponentiation_component_test_case) {

    test_all_set_commitment_components<curves::bls12<381>>();
    test_all_set_commitment_components<curves::mnt4<298>>();
    test_all_set_commitment_components<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_SUITE_END()
