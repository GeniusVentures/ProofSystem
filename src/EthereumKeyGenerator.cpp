
#include "EthereumKeyPairParams.hpp"
#include "util.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;

class EthereumKeyGenerator {
public:
    // Constructor to generate keys on creation
    EthereumKeyGenerator() :
        privkey(key_gen()),
        pubkey(static_cast<pubkey::public_key<ethereum::policy_type>>(privkey)) {


        ethereum::hash_type::digest_type d = hash<ethereum::hash_type>(pubkey.pubkey_data().X.data());

        // Extract address from public key
        auto address_bytes = hashes::keccak_1600<256>(pubkey.pubkey_data().X.data());
        address = util::to_string(address_bytes);
        address = "0x" + address.substr(address.size() - 40);
    }

    // Getter for private key (be careful with security implications)
    [[nodiscard]] const pubkey::private_key<ethereum::policy_type>& get_private_key() const { return privkey; }

    // Getter for public key
    [[nodiscard]] const pubkey::public_key<ethereum::policy_type>& get_public_key() const { return pubkey; }

    // Getter for address
    [[nodiscard]] const std::string& get_address() const { return address; }

    static inline ethereum::scalar_field_value_type gen()
    {
        ethereum::generator_type key_gen;
        return key_gen();
    };

private:
    ethereum::generator_type key_gen;
    pubkey::private_key<ethereum::policy_type> privkey;
    pubkey::public_key<ethereum::policy_type> pubkey;
    std::string address;
};
