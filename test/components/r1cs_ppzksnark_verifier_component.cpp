//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_ppzksnark_verifier_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp3_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp4_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp6_components.hpp>
#include <nil/crypto3/zk/snark/components/verifiers/r1cs_ppzksnark_verifier_component.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void dump_constraints(const blueprint<FieldType> &pb) {
#ifdef DEBUG
    for (auto s : pb.constraint_system.constraint_annotations) {
        printf("constraint: %s\n", s.second.c_str());
    }
#endif
}

template<typename ppT_A, typename ppT_B>
void test_verifier(const std::string &annotation_A, const std::string &annotation_B) {
    typedef typename ppT_A::scalar_field_type FieldT_A;
    typedef typename ppT_B::scalar_field_type FieldT_B;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    r1cs_example<FieldT_A> example =
        generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    BOOST_CHECK(example.primary_input.size() == primary_input_size);

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);
    const r1cs_ppzksnark_proof<ppT_A> pi =
        r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, example.primary_input, pi);
    BOOST_CHECK(bit);

    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const size_t vk_size_in_bits = r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    blueprint<FieldT_B> pb;
    blueprint_variable_vector<FieldT_B> vk_bits;
    vk_bits.allocate(pb, vk_size_in_bits);

    blueprint_variable_vector<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(pb, primary_input_size_in_bits);

    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb);

    r1cs_ppzksnark_verification_key_variable<ppT_B> vk(pb, vk_bits, primary_input_size);

    variable<FieldT_B> result;
    result.allocate(pb);

    r1cs_ppzksnark_verifier_component<ppT_B> verifier(pb, vk, primary_input_bits, elt_size, proof, result);

    proof.generate_r1cs_constraints();
    verifier.generate_r1cs_constraints();

    std::vector<bool> input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        std::vector<bool> v = algebra::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("positive test:\n");
    BOOST_CHECK(pb.is_satisfied());

    pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("negative test:\n");
    BOOST_CHECK(!pb.is_satisfied());
    printf(
        "number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
        pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}

template<typename ppT_A, typename ppT_B>
void test_hardcoded_verifier(const std::string &annotation_A, const std::string &annotation_B) {
    typedef typename ppT_A::scalar_field_type FieldT_A;
    typedef typename ppT_B::scalar_field_type FieldT_B;

    const size_t num_constraints = 50;
    const size_t primary_input_size = 3;

    r1cs_example<FieldT_A> example =
        generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    BOOST_CHECK(example.primary_input.size() == primary_input_size);

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);
    const r1cs_ppzksnark_proof<ppT_A> pi =
        r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = r1cs_ppzksnark_verifier_strong_IC<ppT_A>(keypair.vk, example.primary_input, pi);
    BOOST_CHECK(bit);

    const size_t elt_size = FieldT_A::size_in_bits();
    const size_t primary_input_size_in_bits = elt_size * primary_input_size;

    blueprint<FieldT_B> pb;
    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT_B> hardcoded_vk(pb, keypair.vk);
    blueprint_variable_vector<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(pb, primary_input_size_in_bits);

    r1cs_ppzksnark_proof_variable<ppT_B> proof(pb);

    variable<FieldT_B> result;
    result.allocate(pb);

    r1cs_ppzksnark_online_verifier_component<ppT_B> online_verifier(pb, hardcoded_vk, primary_input_bits, elt_size,
                                                                    proof, result);

    proof.generate_r1cs_constraints();
    online_verifier.generate_r1cs_constraints();

    std::vector<bool> input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        std::vector<bool> v = algebra::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(pb, input_as_bits);

    proof.generate_r1cs_witness(pi);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("positive test:\n");
    BOOST_CHECK(pb.is_satisfied());

    pb.val(primary_input_bits[0]) = FieldT_B::one() - pb.val(primary_input_bits[0]);
    online_verifier.generate_r1cs_witness();
    pb.val(result) = FieldT_B::one();

    printf("negative test:\n");
    BOOST_CHECK(!pb.is_satisfied());
    printf(
        "number of constraints for verifier: %zu (verifier is implemented in %s constraints and verifies %s proofs))\n",
        pb.num_constraints(), annotation_B.c_str(), annotation_A.c_str());
}

template<typename FpExtT, template<class> class VarT, template<class> class MulT>
void test_mul(const std::string &annotation) {
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> pb;
    VarT<FpExtT> x(pb);
    VarT<FpExtT> y(pb);
    VarT<FpExtT> xy(pb);
    MulT<FpExtT> mul(pb, x, y, xy);
    mul.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        const typename FpExtT::value_type x_val = random_element<FpExtT>();
        const typename FpExtT::value_type y_val = random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        y.generate_r1cs_witness(y_val);
        mul.generate_r1cs_witness();
        const typename FpExtT::value_type res = xy.get_element();
        BOOST_CHECK(res == x_val * y_val);
        BOOST_CHECK(pb.is_satisfied());
    }
    printf("number of constraints for %s_mul = %zu\n", annotation.c_str(), pb.num_constraints());
}

template<typename FpExtT, template<class> class VarT, template<class> class SqrT>
void test_sqr(const std::string &annotation) {
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> pb;
    VarT<FpExtT> x(pb);
    VarT<FpExtT> xsq(pb);
    SqrT<FpExtT> sqr(pb, x, xsq);
    sqr.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        const typename FpExtT::value_type x_val = random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        sqr.generate_r1cs_witness();
        const typename FpExtT::value_type res = xsq.get_element();
        BOOST_CHECK(res == x_val.squared());
        BOOST_CHECK(pb.is_satisfied());
    }
    printf("number of constraints for %s_sqr = %zu\n", annotation.c_str(), pb.num_constraints());
}

template<typename CurveType, template<class> class VarT, template<class> class CycloSqrT>
void test_cyclotomic_sqr(const std::string &annotation) {
    typedef algebra::Fqk<CurveType> FpExtT;
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> pb;
    VarT<FpExtT> x(pb);
    VarT<FpExtT> xsq(pb);
    CycloSqrT<FpExtT> sqr(pb, x, xsq);
    sqr.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        FpExtT x_val = random_element<FpExtT>();
        x_val = final_exponentiation<CurveType>(x_val);

        x.generate_r1cs_witness(x_val);
        sqr.generate_r1cs_witness();
        const typename FpExtT::value_type res = xsq.get_element();
        BOOST_CHECK(res == x_val.squared());
        BOOST_CHECK(pb.is_satisfied());
    }
    printf("number of constraints for %s_cyclotomic_sqr = %zu\n", annotation.c_str(), pb.num_constraints());
}

template<typename FpExtT, template<class> class VarT>
void test_Frobenius(const std::string &annotation) {
    typedef typename FpExtT::my_Fp FieldType;

    for (size_t i = 0; i < 100; ++i) {
        blueprint<FieldType> pb;
        VarT<FpExtT> x(pb);
        VarT<FpExtT> x_frob = x.Frobenius_map(i);

        const typename FpExtT::value_type x_val = random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        x_frob.evaluate();
        const typename FpExtT::value_type res = x_frob.get_element();
        BOOST_CHECK(res == x_val.Frobenius_map(i));
        BOOST_CHECK(pb.is_satisfied());
    }

    printf("Frobenius map for %s correct\n", annotation.c_str());
}

template<typename CurveType>
void test_full_pairing(const std::string &annotation) {
    typedef typename CurveType::scalar_field_type FieldType;

    blueprint<FieldType> pb;
    other_curve<CurveType>::g1_type P_val =
        random_element<other_curve<CurveType>::scalar_field_type>() * other_curve<CurveType>::g1_type::one();
    other_curve<CurveType>::g2_type Q_val =
        random_element<other_curve<CurveType>::scalar_field_type>() * other_curve<CurveType>::g2_type::one();

    G1_variable<CurveType> P(pb);
    G2_variable<CurveType> Q(pb);
    G1_precomputation<CurveType> prec_P;
    G2_precomputation<CurveType> prec_Q;

    precompute_G1_component<CurveType> compute_prec_P(pb, P, prec_P);
    precompute_G2_component<CurveType> compute_prec_Q(pb, Q, prec_Q);

    Fqk_variable<CurveType> miller_result(pb);
    mnt_miller_loop_component<CurveType> miller(pb, prec_P, prec_Q, miller_result);
    variable<FieldType> result_is_one;
    result_is_one.allocate(pb);
    final_exp_component<CurveType> finexp(pb, miller_result, result_is_one);

    compute_prec_P.generate_r1cs_constraints();
    compute_prec_Q.generate_r1cs_constraints();
    miller.generate_r1cs_constraints();
    finexp.generate_r1cs_constraints();

    P.generate_r1cs_witness(P_val);
    compute_prec_P.generate_r1cs_witness();
    Q.generate_r1cs_witness(Q_val);
    compute_prec_Q.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    finexp.generate_r1cs_witness();
    BOOST_CHECK(pb.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<CurveType>> native_prec_P =
        other_curve<CurveType>::affine_ate_precompute_G1(P_val);
    algebra::affine_ate_G2_precomp<other_curve<CurveType>> native_prec_Q =
        other_curve<CurveType>::affine_ate_precompute_G2(Q_val);
    algebra::Fqk<other_curve<CurveType>> native_miller_result =
        other_curve<CurveType>::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    algebra::Fqk<other_curve<CurveType>> native_finexp_result =
        other_curve<CurveType>::final_exponentiation(native_miller_result);
    printf("Must match:\n");
    finexp.result->get_element().print();
    native_finexp_result.print();

    BOOST_CHECK(finexp.result->get_element() == native_finexp_result);

    printf("number of constraints for full pairing (Fr is %s)  = %zu\n", annotation.c_str(), pb.num_constraints());
}

template<typename CurveType>
void test_full_precomputed_pairing(const std::string &annotation) {
    typedef typename CurveType::scalar_field_type FieldType;

    blueprint<FieldType> pb;
    other_curve<CurveType>::g1_type P_val =
        random_element<other_curve<CurveType>::scalar_field_type>() * other_curve<CurveType>::g1_type::one();
    other_curve<CurveType>::g2_type Q_val =
        random_element<other_curve<CurveType>::scalar_field_type>() * other_curve<CurveType>::g2_type::one();

    G1_precomputation<CurveType> prec_P(pb, P_val);
    G2_precomputation<CurveType> prec_Q(pb, Q_val);

    Fqk_variable<CurveType> miller_result(pb);
    mnt_miller_loop_component<CurveType> miller(pb, prec_P, prec_Q, miller_result);
    variable<FieldType> result_is_one;
    result_is_one.allocate(pb);
    final_exp_component<CurveType> finexp(pb, miller_result, result_is_one);

    miller.generate_r1cs_constraints();
    finexp.generate_r1cs_constraints();

    miller.generate_r1cs_witness();
    finexp.generate_r1cs_witness();
    BOOST_CHECK(pb.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<CurveType>> native_prec_P =
        other_curve<CurveType>::affine_ate_precompute_G1(P_val);
    algebra::affine_ate_G2_precomp<other_curve<CurveType>> native_prec_Q =
        other_curve<CurveType>::affine_ate_precompute_G2(Q_val);
    algebra::Fqk<other_curve<CurveType>> native_miller_result =
        other_curve<CurveType>::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    algebra::Fqk<other_curve<CurveType>> native_finexp_result =
        other_curve<CurveType>::final_exponentiation(native_miller_result);
    printf("Must match:\n");
    finexp.result->get_element().print();
    native_finexp_result.print();

    BOOST_CHECK(finexp.result->get_element() == native_finexp_result);

    printf("number of constraints for full precomputed pairing (Fr is %s)  = %zu\n", annotation.c_str(),
           pb.num_constraints());
}

template<typename ppT>
void test_mnt_e_times_e_over_e_miller_loop(const std::string &annotation) {
    protoboard<algebra::Fr<ppT>> pb;
    algebra::G1<other_curve<ppT>> P1_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q1_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    algebra::G1<other_curve<ppT>> P2_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q2_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    algebra::G1<other_curve<ppT>> P3_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q3_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    G1_variable<ppT> P1(pb, "P1");
    G2_variable<ppT> Q1(pb, "Q1");
    G1_variable<ppT> P2(pb, "P2");
    G2_variable<ppT> Q2(pb, "Q2");
    G1_variable<ppT> P3(pb, "P3");
    G2_variable<ppT> Q3(pb, "Q3");

    G1_precomputation<ppT> prec_P1;
    precompute_G1_gadget<ppT> compute_prec_P1(pb, P1, prec_P1, "compute_prec_P1");
    G1_precomputation<ppT> prec_P2;
    precompute_G1_gadget<ppT> compute_prec_P2(pb, P2, prec_P2, "compute_prec_P2");
    G1_precomputation<ppT> prec_P3;
    precompute_G1_gadget<ppT> compute_prec_P3(pb, P3, prec_P3, "compute_prec_P3");
    G2_precomputation<ppT> prec_Q1;
    precompute_G2_gadget<ppT> compute_prec_Q1(pb, Q1, prec_Q1, "compute_prec_Q1");
    G2_precomputation<ppT> prec_Q2;
    precompute_G2_gadget<ppT> compute_prec_Q2(pb, Q2, prec_Q2, "compute_prec_Q2");
    G2_precomputation<ppT> prec_Q3;
    precompute_G2_gadget<ppT> compute_prec_Q3(pb, Q3, prec_Q3, "compute_prec_Q3");

    Fqk_variable<ppT> result(pb, "result");
    mnt_e_times_e_over_e_miller_loop_gadget<ppT> miller(pb, prec_P1, prec_Q1, prec_P2, prec_Q2, prec_P3, prec_Q3,
                                                        result, "miller");

    PROFILE_CONSTRAINTS(pb, "precompute P") {
        compute_prec_P1.generate_r1cs_constraints();
        compute_prec_P2.generate_r1cs_constraints();
        compute_prec_P3.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "precompute Q") {
        compute_prec_Q1.generate_r1cs_constraints();
        compute_prec_Q2.generate_r1cs_constraints();
        compute_prec_Q3.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "Miller loop") {
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P1.generate_r1cs_witness(P1_val);
    compute_prec_P1.generate_r1cs_witness();
    Q1.generate_r1cs_witness(Q1_val);
    compute_prec_Q1.generate_r1cs_witness();
    P2.generate_r1cs_witness(P2_val);
    compute_prec_P2.generate_r1cs_witness();
    Q2.generate_r1cs_witness(Q2_val);
    compute_prec_Q2.generate_r1cs_witness();
    P3.generate_r1cs_witness(P3_val);
    compute_prec_P3.generate_r1cs_witness();
    Q3.generate_r1cs_witness(Q3_val);
    compute_prec_Q3.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(pb.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P1 =
        other_curve<ppT>::affine_ate_precompute_G1(P1_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q1 =
        other_curve<ppT>::affine_ate_precompute_G2(Q1_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P2 =
        other_curve<ppT>::affine_ate_precompute_G1(P2_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q2 =
        other_curve<ppT>::affine_ate_precompute_G2(Q2_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P3 =
        other_curve<ppT>::affine_ate_precompute_G1(P3_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q3 =
        other_curve<ppT>::affine_ate_precompute_G2(Q3_val);
    algebra::Fqk<other_curve<ppT>> native_result =
        (other_curve<ppT>::affine_ate_miller_loop(native_prec_P1, native_prec_Q1) *
         other_curve<ppT>::affine_ate_miller_loop(native_prec_P2, native_prec_Q2) *
         other_curve<ppT>::affine_ate_miller_loop(native_prec_P3, native_prec_Q3).inverse());

    BOOST_CHECK(result.get_element() == native_result);
    printf("number of constraints for e times e over e Miller loop (Fr is %s)  = %zu\n", annotation.c_str(),
           pb.num_constraints());
}

template<typename ppT>
void test_mnt_miller_loop(const std::string &annotation) {
    protoboard<algebra::Fr<ppT>> pb;
    algebra::G1<other_curve<ppT>> P_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    G1_variable<ppT> P(pb, "P");
    G2_variable<ppT> Q(pb, "Q");

    G1_precomputation<ppT> prec_P;
    G2_precomputation<ppT> prec_Q;

    precompute_G1_gadget<ppT> compute_prec_P(pb, P, prec_P, "prec_P");
    precompute_G2_gadget<ppT> compute_prec_Q(pb, Q, prec_Q, "prec_Q");

    Fqk_variable<ppT> result(pb, "result");
    mnt_miller_loop_gadget<ppT> miller(pb, prec_P, prec_Q, result, "miller");

    PROFILE_CONSTRAINTS(pb, "precompute P") {
        compute_prec_P.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "precompute Q") {
        compute_prec_Q.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "Miller loop") {
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P.generate_r1cs_witness(P_val);
    compute_prec_P.generate_r1cs_witness();
    Q.generate_r1cs_witness(Q_val);
    compute_prec_Q.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(pb.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P = other_curve<ppT>::affine_ate_precompute_G1(P_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q = other_curve<ppT>::affine_ate_precompute_G2(Q_val);
    algebra::Fqk<other_curve<ppT>> native_result =
        other_curve<ppT>::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    BOOST_CHECK(result.get_element() == native_result);
    printf("number of constraints for Miller loop (Fr is %s)  = %zu\n", annotation.c_str(), pb.num_constraints());
}

template<typename ppT>
void test_mnt_e_over_e_miller_loop(const std::string &annotation) {
    protoboard<algebra::Fr<ppT>> pb;
    algebra::G1<other_curve<ppT>> P1_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q1_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    algebra::G1<other_curve<ppT>> P2_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G1<other_curve<ppT>>::one();
    algebra::G2<other_curve<ppT>> Q2_val =
        algebra::Fr<other_curve<ppT>>::random_element() * algebra::G2<other_curve<ppT>>::one();

    G1_variable<ppT> P1(pb, "P1");
    G2_variable<ppT> Q1(pb, "Q1");
    G1_variable<ppT> P2(pb, "P2");
    G2_variable<ppT> Q2(pb, "Q2");

    G1_precomputation<ppT> prec_P1;
    precompute_G1_gadget<ppT> compute_prec_P1(pb, P1, prec_P1, "compute_prec_P1");
    G1_precomputation<ppT> prec_P2;
    precompute_G1_gadget<ppT> compute_prec_P2(pb, P2, prec_P2, "compute_prec_P2");
    G2_precomputation<ppT> prec_Q1;
    precompute_G2_gadget<ppT> compute_prec_Q1(pb, Q1, prec_Q1, "compute_prec_Q1");
    G2_precomputation<ppT> prec_Q2;
    precompute_G2_gadget<ppT> compute_prec_Q2(pb, Q2, prec_Q2, "compute_prec_Q2");

    Fqk_variable<ppT> result(pb, "result");
    mnt_e_over_e_miller_loop_gadget<ppT> miller(pb, prec_P1, prec_Q1, prec_P2, prec_Q2, result, "miller");

    PROFILE_CONSTRAINTS(pb, "precompute P") {
        compute_prec_P1.generate_r1cs_constraints();
        compute_prec_P2.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "precompute Q") {
        compute_prec_Q1.generate_r1cs_constraints();
        compute_prec_Q2.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(pb, "Miller loop") {
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P1.generate_r1cs_witness(P1_val);
    compute_prec_P1.generate_r1cs_witness();
    Q1.generate_r1cs_witness(Q1_val);
    compute_prec_Q1.generate_r1cs_witness();
    P2.generate_r1cs_witness(P2_val);
    compute_prec_P2.generate_r1cs_witness();
    Q2.generate_r1cs_witness(Q2_val);
    compute_prec_Q2.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(pb.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P1 =
        other_curve<ppT>::affine_ate_precompute_G1(P1_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q1 =
        other_curve<ppT>::affine_ate_precompute_G2(Q1_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P2 =
        other_curve<ppT>::affine_ate_precompute_G1(P2_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q2 =
        other_curve<ppT>::affine_ate_precompute_G2(Q2_val);
    algebra::Fqk<other_curve<ppT>> native_result =
        (other_curve<ppT>::affine_ate_miller_loop(native_prec_P1, native_prec_Q1) *
         other_curve<ppT>::affine_ate_miller_loop(native_prec_P2, native_prec_Q2).inverse());

    BOOST_CHECK(result.get_element() == native_result);
    printf("number of constraints for e over e Miller loop (Fr is %s)  = %zu\n", annotation.c_str(),
           pb.num_constraints());
}

int main() {
    test_mul<algebra::mnt4_Fq2, Fp2_variable, Fp2_mul_component>("mnt4_Fp2");
    test_sqr<algebra::mnt4_Fq2, Fp2_variable, Fp2_sqr_component>("mnt4_Fp2");

    test_mul<algebra::mnt4_Fq4, Fp4_variable, Fp4_mul_component>("mnt4_Fp4");
    test_sqr<algebra::mnt4_Fq4, Fp4_variable, Fp4_sqr_component>("mnt4_Fp4");
    test_cyclotomic_sqr<curves::mnt4, Fp4_variable, Fp4_cyclotomic_sqr_component>("mnt4_Fp4");
    test_exponentiation_component<algebra::mnt4_Fq4, Fp4_variable, Fp4_mul_component, Fp4_sqr_component,
                                  algebra::mnt4_q_limbs>(algebra::mnt4_final_exponent_last_chunk_abs_of_w0, "mnt4_Fq4");
    test_Frobenius<algebra::mnt4_Fq4, Fp4_variable>("mnt4_Fq4");

    test_mul<algebra::mnt6_Fq3, Fp3_variable, Fp3_mul_component>("mnt6_Fp3");
    test_sqr<algebra::mnt6_Fq3, Fp3_variable, Fp3_sqr_component>("mnt6_Fp3");

    test_mul<algebra::mnt6_Fq6, Fp6_variable, Fp6_mul_component>("mnt6_Fp6");
    test_sqr<algebra::mnt6_Fq6, Fp6_variable, Fp6_sqr_component>("mnt6_Fp6");
    test_cyclotomic_sqr<curves::mnt6, Fp6_variable, Fp6_cyclotomic_sqr_component>("mnt6_Fp6");
    test_exponentiation_component<algebra::mnt6_Fq6, Fp6_variable, Fp6_mul_component, Fp6_sqr_component,
                                  algebra::mnt6_q_limbs>(algebra::mnt6_final_exponent_last_chunk_abs_of_w0, "mnt6_Fq6");
    test_Frobenius<algebra::mnt6_Fq6, Fp6_variable>("mnt6_Fq6");

    test_G2_checker_component<curves::mnt4>("mnt4");
    test_G2_checker_component<curves::mnt6>("mnt6");

    test_G1_variable_precomp<curves::mnt4>("mnt4");
    test_G1_variable_precomp<curves::mnt6>("mnt6");

    test_G2_variable_precomp<curves::mnt4>("mnt4");
    test_G2_variable_precomp<curves::mnt6>("mnt6");

    test_mnt_miller_loop<curves::mnt4>("mnt4");
    test_mnt_miller_loop<curves::mnt6>("mnt6");

    test_mnt_e_over_e_miller_loop<curves::mnt4>("mnt4");
    test_mnt_e_over_e_miller_loop<curves::mnt6>("mnt6");

    test_mnt_e_times_e_over_e_miller_loop<curves::mnt4>("mnt4");
    test_mnt_e_times_e_over_e_miller_loop<curves::mnt6>("mnt6");

    test_full_pairing<curves::mnt4>("mnt4");
    test_full_pairing<curves::mnt6>("mnt6");

    test_full_precomputed_pairing<curves::mnt4>("mnt4");
    test_full_precomputed_pairing<curves::mnt6>("mnt6");

    test_verifier<curves::mnt4, curves::mnt6>("mnt4", "mnt6");
    test_verifier<curves::mnt6, curves::mnt4>("mnt6", "mnt4");

    test_hardcoded_verifier<curves::mnt4, curves::mnt6>("mnt4", "mnt6");
    test_hardcoded_verifier<curves::mnt6, curves::mnt4>("mnt6", "mnt4");
}