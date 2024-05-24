#include <nil/crypto3/random/hash.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/hash/sha2.hpp>

int main() {
    using field_type = typename ::nil::crypto3::algebra::curves::mnt4<298>::scalar_field_type;
    using field_value_type = typename field_type::value_type;
    using hash_type = hashes::sha2<512>;
    using rng_engine = ::nil::crypto3::random::hash<::nil::crypto3::hashes::sha2<512>, field_value_type>;

    // Create engine instance with default seed (0)
    rng_engine re1;

    // Create engine instance with custom seed (any std::uint64_t number)
    rng_engine re2(123);

    // Get random value for supplied seed
    auto rval1 = re1();
    auto rval2 = re2();

    // Update seed
    re1.seed(5);

    // Get supplied seed and put it into stream
    std::cout << re1 << std::endl;

    // Advance state (irrelevant for this specific engine)
    re1.discard(100);

    return 0;
}