#define BOOST_TEST_MODULE kimchi_commitment_test

#include <string>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdlib>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/kimchi_pedersen.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail/mapping.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using curve_type = algebra::curves::vesta;
using group_type = curve_type::template g1_type<algebra::curves::coordinates::affine>;
using scalar_field_type = curve_type::scalar_field_type;
using base_field_type = curve_type::base_field_type;
using scalar_value_type = scalar_field_type::value_type;
using kimchi_pedersen = commitments::kimchi_pedersen<curve_type>;
using sponge_type = kimchi_pedersen::sponge_type;
using params_type = kimchi_pedersen::params_type;
using batchproof_type = kimchi_pedersen::batchproof_type;
using commitment_type = kimchi_pedersen::commitment_type;
using blinding_type = kimchi_pedersen::blinding_type;
using proof_type = kimchi_pedersen::proof_type;
using polynomial_type = kimchi_pedersen::polynomial_type;
using polynomial_type_single = kimchi_pedersen::polynomial_type_single;
using evaluation_type = kimchi_pedersen::evaluation_type;
using blinded_commitment_type = kimchi_pedersen::blinded_commitment_type;

struct Commitment {
    /// the commitment itself, potentially in chunks
    commitment_type chunked_commitment;

    /// an optional degree bound
    std::size_t bound;
};

/// An evaluated commitment (given a number of evaluation points)
struct evaluated_commitment {
    /// the commitment
    Commitment commit;

    /// the chunked evaluations given in the same order as the evaluation points
    std::vector<std::vector<scalar_value_type>> chunked_evals;
};

struct CommitmentAndSecrets {
    /// the commitment evaluated at some points
    evaluated_commitment eval_commit;

    /// the polynomial
    math::polynomial<scalar_field_type::value_type> poly;

    /// the blinding part
    blinding_type chunked_blinding;
};

struct aggregated_evaluation_proof {
    /// a number of evaluation points
    std::vector<scalar_value_type> eval_points;

    /// a number of commitments evaluated at these evaluation points
    std::vector<evaluated_commitment> eval_commitments;

    /// the random value used to separate polynomials
    scalar_value_type polymask;

    /// the random value used to separate evaluations
    scalar_value_type evalmask;

    /// an Fq-sponge
    sponge_type fq_sponge;

    /// the actual evaluation proof
    proof_type proof;

    batchproof_type verify_type() {
        std::vector<evaluation_type> coms;

        for (auto &eval_com: eval_commitments) {
            assert(eval_points.size() == eval_com.chunked_evals.size());
            coms.push_back(
                    evaluation_type(
                            {eval_com.commit.chunked_commitment, eval_com.chunked_evals, (int) eval_com.commit.bound}));
        }

        return batchproof_type({fq_sponge, coms, eval_points, polymask, evalmask, proof});
    }
};

struct chunked_polynomial {
    std::vector<math::polynomial<scalar_value_type>> chunked_polynomials;
    unsigned int chunk_size;

    chunked_polynomial(math::polynomial<scalar_value_type> &big_polynomial, unsigned int chunk_size) :
            chunk_size(chunk_size) {
        unsigned int number_of_chunks =
                big_polynomial.size() / chunk_size + (big_polynomial.size() % chunk_size ? 1 : 0);

        for (unsigned int i = 0; i < number_of_chunks; ++i) {
            auto iter_chunk_begin = big_polynomial.begin() + i * chunk_size;
            auto iter_chunk_end =
                    big_polynomial.begin() + (i == number_of_chunks - 1 ? big_polynomial.size() : (i + 1) * chunk_size);
            chunked_polynomials.emplace_back(iter_chunk_begin, iter_chunk_end);
        }
    }

    std::vector<scalar_value_type> evaluate_chunks(scalar_value_type &point) {
        std::vector<scalar_value_type> result;

        for (auto &a: chunked_polynomials) {
            result.push_back(a.evaluate(point));
        }

        return result;
    }
};

BOOST_AUTO_TEST_SUITE(kimchi_commitment_test_suite)

    BOOST_AUTO_TEST_CASE(kimchi_commitment_test_opening_proof) {
        snark::group_map<curve_type> g_map;
        sponge_type fq_sponge;
        params_type params = kimchi_pedersen::setup(20);

        std::vector<scalar_value_type> coeffs;
        for (int i = 0; i < 10; ++i) {
            coeffs.emplace_back(i);
        }

        math::polynomial<scalar_value_type> poly1(coeffs);
        math::polynomial<scalar_value_type> poly2(coeffs.begin(), coeffs.begin() + 5);

        blinded_commitment_type commitment = kimchi_pedersen::commitment(params, poly1, -1);
        blinded_commitment_type bounded_commitment = kimchi_pedersen::commitment(params, poly2, poly2.degree() + 1);

        scalar_value_type u = algebra::random_element<scalar_field_type>();
        scalar_value_type v = algebra::random_element<scalar_field_type>();

        polynomial_type polys{{poly1, -1,                                   std::get<1>(commitment)},
                              {poly2, static_cast<int>(poly2.degree() + 1), std::get<1>(bounded_commitment)}};

        std::vector<scalar_value_type> elm{algebra::random_element<scalar_field_type>(),
                                           algebra::random_element<scalar_field_type>()};

        proof_type proof = kimchi_pedersen::proof_eval(params, g_map, polys, elm, v, u, fq_sponge);

        chunked_polynomial poly1_chunked(poly1, params.g.size());
        chunked_polynomial poly2_chunked(poly2, params.g.size());

        std::vector<std::vector<scalar_value_type>> poly1_chunked_evals = {poly1_chunked.evaluate_chunks(elm[0]),
                                                                           poly1_chunked.evaluate_chunks(elm[1])};
        std::vector<std::vector<scalar_value_type>> poly2_chunked_evals = {poly2_chunked.evaluate_chunks(elm[0]),
                                                                           poly2_chunked.evaluate_chunks(elm[1])};

        std::vector<evaluation_type> evals;
        evals.emplace_back(std::get<0>(commitment), poly1_chunked_evals, -1);
        evals.emplace_back(std::get<0>(bounded_commitment), poly2_chunked_evals, poly2.degree() + 1);
        sponge_type new_fq_sponge;
        std::vector<batchproof_type> batch;
        batch.emplace_back(new_fq_sponge, evals, elm, v, u, proof);

        BOOST_CHECK(kimchi_pedersen::verify_eval(params, g_map, batch));
    }

    BOOST_AUTO_TEST_CASE(kimchi_commitment_test_case) {

        snark::group_map<curve_type> g_map;
        sponge_type fq_sponge;
        params_type params = kimchi_pedersen::setup(1 << 7);

        std::vector<aggregated_evaluation_proof> proofs;

        std::size_t count_eval_proofs = 1;
        for (std::size_t i = 0; i < count_eval_proofs; ++i) {
            std::vector<scalar_value_type> eval_points(7);

            // Random_element is called with the default parameter, yet we need to wrap it in a lamda.
            std::generate(eval_points.begin(), eval_points.end(),
                          []() { return algebra::random_element<scalar_field_type>(); });

            std::vector<CommitmentAndSecrets> commitments;

            for (unsigned int i = 0; i < 3; ++i) {
                unsigned int len = std::rand() % 500;
                std::vector<scalar_value_type> polynom_coeffs(len);

                // Random_element is called with the default parameter, yet we need to wrap it in a lamda.
                std::generate(polynom_coeffs.begin(), polynom_coeffs.end(),
                              []() { return algebra::random_element<scalar_field_type>(); });
                unsigned int bound = polynom_coeffs.size();

                math::polynomial<scalar_value_type> poly(polynom_coeffs.begin(), polynom_coeffs.end());

                blinded_commitment_type blinded_commitment = kimchi_pedersen::commitment(params, poly, bound);

                std::vector<std::vector<scalar_value_type>> chunked_evals;

                chunked_polynomial chunked_poly(poly, params.g.size());

                for (auto &point: eval_points) {
                    chunked_evals.emplace_back(chunked_poly.evaluate_chunks(point));
                }

                Commitment commit{std::get<0>(blinded_commitment), bound};
                evaluated_commitment eval_commit{commit, chunked_evals};
                commitments.emplace_back(CommitmentAndSecrets({eval_commit, poly, std::get<1>(blinded_commitment)}));
            }

            polynomial_type polynomials;

            for (auto &c: commitments) {
                polynomials.emplace_back(c.poly, c.eval_commit.commit.bound, c.chunked_blinding);
            }

            scalar_value_type polymask = algebra::random_element<scalar_field_type>();
            scalar_value_type evalmask = algebra::random_element<scalar_field_type>();

            proof_type proof =
                    kimchi_pedersen::proof_eval(params, g_map, polynomials, eval_points, polymask, evalmask, fq_sponge);

            std::vector<evaluated_commitment> eval_commitments;
            for (auto &c: commitments) {
                eval_commitments.emplace_back(c.eval_commit);
            }

            sponge_type new_fq_sponge;
            proofs.emplace_back(
                    aggregated_evaluation_proof(
                            {eval_points, eval_commitments, polymask, evalmask, new_fq_sponge, proof}));
        }

        std::vector<batchproof_type> batch;
        for (auto &proof: proofs) {
            batch.emplace_back(proof.verify_type());
        }

        BOOST_CHECK(kimchi_pedersen::verify_eval(params, g_map, batch));
    }

BOOST_AUTO_TEST_SUITE_END()
