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
using poly_type = kimchi_pedersen::poly_type;
using poly_type_single = kimchi_pedersen::poly_type_single;
using evaluation_type = kimchi_pedersen::evaluation_type;
using blinded_commitment_type = kimchi_pedersen::blinded_commitment_type;

struct Commitment {
    /// the commitment itself, potentially in chunks
    commitment_type chunked_commitment;

    /// an optional degree bound
    unsigned int bound;
};

/// An evaluated commitment (given a number of evaluation points)
struct EvaluatedCommitment {
    /// the commitment
    Commitment commit;

    /// the chunked evaluations given in the same order as the evaluation points
    std::vector<std::vector<scalar_value_type>> chunked_evals;
};

struct CommitmentAndSecrets {
    /// the commitment evaluated at some points
    EvaluatedCommitment eval_commit;

    /// the polynomial
    math::polynomial<scalar_field_type::value_type> poly;

    /// the blinding part
    blinding_type chunked_blinding;
};

struct AggregatedEvaluationProof {
    /// a number of evaluation points
    std::vector<scalar_value_type> eval_points;

    /// a number of commitments evaluated at these evaluation points
    std::vector<EvaluatedCommitment> eval_commitments;

    /// the random value used to separate polynomials
    scalar_value_type polymask;

    /// the random value used to separate evaluations
    scalar_value_type evalmask;

    /// an Fq-sponge
    sponge_type fq_sponge;

    /// the actual evaluation proof
    proof_type proof;

    batchproof_type verify_type(){
        std::vector<evaluation_type> coms;

        for(auto &eval_com : eval_commitments){
            assert(eval_points.size() == eval_com.chunked_evals.size());
            coms.push_back(evaluation_type({eval_com.commit.chunked_commitment, eval_com.chunked_evals, eval_com.commit.bound}));
        }

        return batchproof_type({
            fq_sponge,
            coms,
            eval_points,
            polymask,
            evalmask,
            proof
        });
    }
};

struct chunked_polynomial {
    std::vector<math::polynomial<scalar_value_type> > chunked_polynomials;
    unsigned int chunk_size;

    chunked_polynomial(math::polynomial<scalar_value_type> &big_polynomial, unsigned int chunk_size) : chunk_size(chunk_size) {
        unsigned int number_of_chunks = big_polynomial.size() / chunk_size + (big_polynomial.size() % chunk_size ? 1 : 0);

        for(unsigned int i = 0; i < number_of_chunks; ++i){
            auto iter_chunk_begin = big_polynomial.begin() + i * chunk_size;
            auto iter_chunk_end = big_polynomial.begin() + (i == number_of_chunks - 1 ? big_polynomial.size() : (i + 1) * chunk_size);
            chunked_polynomials.emplace_back(iter_chunk_begin, iter_chunk_end);
        }
    }

    std::vector<scalar_value_type> evaluate_chunks(scalar_value_type &point) {
        std::vector<scalar_value_type> result;

        for(auto &a : chunked_polynomials){
            result.push_back(a.evaluate(point));
        }

        return result;
    }
};

BOOST_AUTO_TEST_SUITE(kimchi_commitment_test_suite)

// BOOST_AUTO_TEST_CASE(kimchi_test_commit){
//     snark::group_map<curve_type> g_map;
//     sponge_type fq_sponge;

//     std::vector<group_type::value_type> g = {group_type::value_type(0x121C4426885FD5A9701385AAF8D43E52E7660F1FC5AFC5F6468CC55312FC60F8_cppui256, 0x21B439C01247EA3518C5DDEB324E4CB108AF617780DDF766D96D3FD8AB028B70_cppui256), 
//                                             group_type::value_type(0x26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26_cppui256, 0x1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504_cppui256), 
//                                             group_type::value_type(0x26985F27306586711466C5B2C28754AA62FE33516D75CEF1F7751F1A169713FD_cppui256, 0x2E8930092FE6A18B331CE0E6E27B413AA18E76394F18A2835DA9FAE10AA3229D_cppui256), 
//                                             group_type::value_type(0x014B2DB7B753A74D454061FCB3AC537E1B4BA512F9ED258C996A59D9DACD13E5_cppui256, 0x06F392D371494FC39174C4B70C692B96F3B7C42DA288F6B7AABF463334A952D0_cppui256), 
//                                             group_type::value_type(0x12CA0E2DBF286021CB76B7C12B6C9AD7FDF1D05F722F6EF14BD43E53E7B92120_cppui256, 0x216A80B79D3995D1F39CE19855C475052D1148ACBDD379FE98961BFBD0A3E428_cppui256), 
//                                             group_type::value_type(0x1D257C1F4EC9872C9E06549BC910F7B7196F2E7CB120AEC3FDCEB049C7A0C9A5_cppui256, 0x191CBEC20ED5EA342B6B395E92996215F7D93C675DA56A13D548EFB58524D336_cppui256), 
//                                             group_type::value_type(0x06236026ED7DC19C44540FBAF0C1C3498F82880A34422547FFF519FFF744BB48_cppui256, 0x3A02C5410DABDE160BD09232A14F00B1EF6CD4D6285C90A8D41FA00BFF922F0A_cppui256), 
//                                             group_type::value_type(0x079333FDE60D3F670068B5A1D486EDDD87DDF91D1E1FC000F387991B4ED848B4_cppui256, 0x3F7FC1A39FD74BDEDC129195080D298CFC2C2CF714BAD9F9334F0DAFB035C200_cppui256), 
//                                             group_type::value_type(0x069B398C2968553B7987FF840CF0B71359D10F249F08C40898550A63F196D856_cppui256, 0x1B68BB879D6EC4EFAA2207E212B59BAD0D8E5E2493F99BE3F2F24764046CD277_cppui256), 
//                                             group_type::value_type(0x2CBD65973AE0BE0B9E652CEC35EFE509E1FA8DD8349DC1E644DB494DC2B4FD75_cppui256, 0x1E27B8178E720407694F4EA1413B0CB87AF4058CB308BBD68FF42D5078DE243E_cppui256), 
//                                             group_type::value_type(0x0F29A22EF6949DE85427F72CCD04E3F8F56837BB56DA17D8FA5DE9025E6B9ED5_cppui256, 0x26A2CD91BD2771E20DECAACDC6CA96E7759668F3D0B7E8810866D27737627A59_cppui256), 
//                                             };

//     group_type::value_type h = group_type::value_type(0x092060386301C999AAB4F263757836369CA27975E28BC7A8E5B2CE5B26262201_cppui256, 0x314FC4D83AE66A509F9D41BE6165F2606A209A9B5805EE85CE20249C5EBCBE26_cppui256);
//     scalar_field_type::value_type endo_r = scalar_field_type::value_type(0x06819A58283E528E511DB4D81CF70F5A0FED467D47C033AF2AA9D2E050AA0E4F_cppui256);
//     base_field_type::value_type endo_q = base_field_type::value_type(0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui256);
//     params_type params(g, h, endo_r, endo_q);

//     std::vector<scalar_value_type> coeffs;
//     for(int i = 0; i < 10; ++i){
//         coeffs.emplace_back(i);
//     }

//     math::polynomial<scalar_value_type> poly1(coeffs);    
//     // math::polynomial<scalar_value_type> poly2(coeffs.begin(), coeffs.begin() + 5);

//     blinded_commitment_type commitment = kimchi_pedersen::commitment(params, poly1, -1);

//     auto commitment_unshifted = std::get<0>(commitment).unshifted;
//     auto commitment_shifted = std::get<0>(commitment).shifted;
//     auto blinded_unshifted = std::get<1>(commitment).unshifted;
//     auto blinded_shifted = std::get<1>(commitment).shifted;
//     for(auto& a : commitment_unshifted){
//         std::cout << std::hex << a.X.data << ' ' << std::hex << a.Y.data << '\n';
//     }
//     for(auto& a : blinded_unshifted){
//         std::cout << std::hex << a.data << '\n';
//     }
//     std::cout << std::hex << commitment_shifted.X.data << ' ' << std::hex << commitment_shifted.Y.data << '\n';
//     // std::cout << std::hex << commitment_shifted.data << '\n';
//     std::cout << std::hex << blinded_shifted.data << '\n';
//     std::cout << commitment_shifted.is_zero() << '\n';
// }

BOOST_AUTO_TEST_CASE(kimchi_commitment_test_opening_proof){
    snark::group_map<curve_type> g_map;
    sponge_type fq_sponge;
    std::vector<group_type::value_type> g = {group_type::value_type(0x121C4426885FD5A9701385AAF8D43E52E7660F1FC5AFC5F6468CC55312FC60F8_cppui256, 0x21B439C01247EA3518C5DDEB324E4CB108AF617780DDF766D96D3FD8AB028B70_cppui256), 
                                            group_type::value_type(0x26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26_cppui256, 0x1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504_cppui256), 
                                            group_type::value_type(0x26985F27306586711466C5B2C28754AA62FE33516D75CEF1F7751F1A169713FD_cppui256, 0x2E8930092FE6A18B331CE0E6E27B413AA18E76394F18A2835DA9FAE10AA3229D_cppui256), 
                                            group_type::value_type(0x014B2DB7B753A74D454061FCB3AC537E1B4BA512F9ED258C996A59D9DACD13E5_cppui256, 0x06F392D371494FC39174C4B70C692B96F3B7C42DA288F6B7AABF463334A952D0_cppui256), 
                                            group_type::value_type(0x12CA0E2DBF286021CB76B7C12B6C9AD7FDF1D05F722F6EF14BD43E53E7B92120_cppui256, 0x216A80B79D3995D1F39CE19855C475052D1148ACBDD379FE98961BFBD0A3E428_cppui256), 
                                            group_type::value_type(0x1D257C1F4EC9872C9E06549BC910F7B7196F2E7CB120AEC3FDCEB049C7A0C9A5_cppui256, 0x191CBEC20ED5EA342B6B395E92996215F7D93C675DA56A13D548EFB58524D336_cppui256), 
                                            group_type::value_type(0x06236026ED7DC19C44540FBAF0C1C3498F82880A34422547FFF519FFF744BB48_cppui256, 0x3A02C5410DABDE160BD09232A14F00B1EF6CD4D6285C90A8D41FA00BFF922F0A_cppui256), 
                                            group_type::value_type(0x079333FDE60D3F670068B5A1D486EDDD87DDF91D1E1FC000F387991B4ED848B4_cppui256, 0x3F7FC1A39FD74BDEDC129195080D298CFC2C2CF714BAD9F9334F0DAFB035C200_cppui256), 
                                            group_type::value_type(0x069B398C2968553B7987FF840CF0B71359D10F249F08C40898550A63F196D856_cppui256, 0x1B68BB879D6EC4EFAA2207E212B59BAD0D8E5E2493F99BE3F2F24764046CD277_cppui256), 
                                            group_type::value_type(0x2CBD65973AE0BE0B9E652CEC35EFE509E1FA8DD8349DC1E644DB494DC2B4FD75_cppui256, 0x1E27B8178E720407694F4EA1413B0CB87AF4058CB308BBD68FF42D5078DE243E_cppui256), 
                                            group_type::value_type(0x0F29A22EF6949DE85427F72CCD04E3F8F56837BB56DA17D8FA5DE9025E6B9ED5_cppui256, 0x26A2CD91BD2771E20DECAACDC6CA96E7759668F3D0B7E8810866D27737627A59_cppui256), 
                                            };

    group_type::value_type h = group_type::value_type(0x092060386301C999AAB4F263757836369CA27975E28BC7A8E5B2CE5B26262201_cppui256, 0x314FC4D83AE66A509F9D41BE6165F2606A209A9B5805EE85CE20249C5EBCBE26_cppui256);
    scalar_field_type::value_type endo_q = scalar_field_type::value_type(0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui256);
    base_field_type::value_type endo_r = base_field_type::value_type(0x06819A58283E528E511DB4D81CF70F5A0FED467D47C033AF2AA9D2E050AA0E4F_cppui256);
    params_type params(g, h, endo_q, endo_r);
    // params_type params = kimchi_pedersen::setup(11);

    std::vector<scalar_value_type> coeffs;
    for(int i = 0; i < 10; ++i){
        coeffs.emplace_back(i);
    }

    math::polynomial<scalar_value_type> poly1(coeffs);    
    math::polynomial<scalar_value_type> poly2(coeffs.begin(), coeffs.begin() + 5);

    blinded_commitment_type commitment = kimchi_pedersen::commitment(params, poly1, -1);
    // blinded_commitment_type bounded_commitment = kimchi_pedersen::commitment(params, poly2, poly2.degree() + 1);

    auto commitment_unshifted = std::get<0>(commitment).unshifted;
    auto commitment_shifted = std::get<0>(commitment).shifted;
    auto blinded_unshifted = std::get<1>(commitment).unshifted;
    auto blinded_shifted = std::get<1>(commitment).shifted;

    // for(auto& a : commitment_unshifted){
    //     std::cout << std::hex << a.X.data << ' ' << std::hex << a.Y.data << '\n';
    // }
    // for(auto& a : blinded_unshifted){
    //     std::cout << std::hex << a.data << '\n';
    // }
    // std::cout << std::hex << commitment_shifted.X.data << ' ' << std::hex << commitment_shifted.Y.data << '\n';
    // // std::cout << std::hex << commitment_shifted.data << '\n';
    // std::cout << std::hex << blinded_shifted.data << '\n';
    // std::cout << commitment_shifted.is_zero() << '\n';



    scalar_value_type u(0x3793E30AC691700012BAF26BB813D6D70BD379BEED8050A1DEEE3C188F1C3FBD_cppui256); // algebra::random_element<scalar_field_type>();
    scalar_value_type v(0x2FC4C98E50E0B1AAE6ECB468E28C0B7D80A7E0EEC7136DB0BA0677B84AF0E465_cppui256); // = algebra::random_element<scalar_field_type>();

    poly_type polys{{poly1, -1, std::get<1>(commitment)},
                    /*{poly2, poly2.degree() + 1, std::get<1>(bounded_commitment)}*/};

    std::vector<scalar_value_type> elm{0x0024FB5773CAC987CF3A17DDD6134BA12D3E1CA4F6C43D3695347747CE61EAF5_cppui256,
                                        0x18E0ED2B46ED1EC258DF721A1D3145B0AA6ABDD02EE851A14B8B659CF47385F2_cppui256};
        //algebra::random_element<scalar_field_type>(), algebra::random_element<scalar_field_type>()};

    proof_type proof = kimchi_pedersen::proof_eval(params, g_map, polys, elm, v, u, fq_sponge);

    chunked_polynomial poly1_chunked(poly1, params.g.size());
    chunked_polynomial poly2_chunked(poly2, params.g.size());

    std::vector< std::vector<scalar_value_type> > poly1_chunked_evals = {poly1_chunked.evaluate_chunks(elm[0]), poly1_chunked.evaluate_chunks(elm[1])};
    std::vector< std::vector<scalar_value_type> > poly2_chunked_evals = {poly2_chunked.evaluate_chunks(elm[0]), poly2_chunked.evaluate_chunks(elm[1])};

    std::vector<evaluation_type> evals;
    evals.emplace_back(std::get<0>(commitment), poly1_chunked_evals, -1);
    // evals.emplace_back(std::get<0>(bounded_commitment), poly2_chunked_evals, poly2.degree() + 1);
    sponge_type new_fq_sponge;
    batchproof_type batch = {new_fq_sponge, evals, elm, v, u, proof};

    BOOST_CHECK(kimchi_pedersen::verify_eval(params, g_map, batch));
}

// BOOST_AUTO_TEST_CASE(kimchi_commitment_test_case){

//     snark::group_map<curve_type> g_map;
//     sponge_type fq_sponge;
//     params_type params = kimchi_pedersen::setup(1 << 7);

//     std::vector<AggregatedEvaluationProof> proofs; 

//     std::size_t count_eval_proofs = 1;
//     for(std::size_t i = 0; i < count_eval_proofs; ++i){
//         std::vector<scalar_value_type> eval_points(7);
//         std::generate(eval_points.begin(), eval_points.end(), algebra::random_element<scalar_field_type>);

//         std::vector<CommitmentAndSecrets> commitments;

//         for(unsigned int i = 0; i < 3; ++i){
//             unsigned int len = std::rand() % 500;
//             std::vector<scalar_value_type> polynom_coeffs(len);

//             std::generate(polynom_coeffs.begin(), polynom_coeffs.end(), algebra::random_element<scalar_field_type>);
//             unsigned int bound = polynom_coeffs.size();

//             math::polynomial<scalar_value_type> poly(polynom_coeffs.begin(), polynom_coeffs.end());
            
//             std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
//             blinded_commitment_type blinded_commitment = kimchi_pedersen::commitment(params, poly, bound);
//             std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
//             std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << "[ms]\n" << std::endl;
            
//             std::vector<std::vector<scalar_value_type>> chunked_evals;
            
//             chunked_polynomial chunked_poly(poly, params.g.size());

//             for(auto &point : eval_points){
//                 chunked_evals.emplace_back(chunked_poly.evaluate_chunks(point));
//             }

//             Commitment commit{std::get<0>(blinded_commitment), bound};
//             EvaluatedCommitment eval_commit{commit, chunked_evals};
//             commitments.emplace_back(CommitmentAndSecrets({eval_commit, poly, std::get<1>(blinded_commitment)}));
//         }

//         poly_type polynomials;
        
//         for(auto &c : commitments){
//             polynomials.emplace_back(c.poly, c.eval_commit.commit.bound, c.chunked_blinding);
//         }

//         scalar_value_type polymask = algebra::random_element<scalar_field_type>();
//         scalar_value_type evalmask = algebra::random_element<scalar_field_type>();

//         proof_type proof = kimchi_pedersen::proof_eval(params, 
//                                                         g_map, 
//                                                         polynomials, 
//                                                         eval_points,
//                                                         polymask,
//                                                         evalmask,
//                                                         fq_sponge);

//         std::vector<EvaluatedCommitment> eval_commitments;
//         for(auto &c : commitments){
//             eval_commitments.emplace_back(c.eval_commit);
//         }

//         proofs.emplace_back(AggregatedEvaluationProof({eval_points, 
//                                                         eval_commitments, 
//                                                         polymask,
//                                                         evalmask,
//                                                         fq_sponge,
//                                                         proof}));
//     }

//     std::vector<batchproof_type> batch;
//     for(auto & proof : proofs){
//         batch.emplace_back(proof.verify_type());
//     }

//     BOOST_CHECK(kimchi_pedersen::verify_eval(params, g_map, batch[0]));
// }

BOOST_AUTO_TEST_SUITE_END()