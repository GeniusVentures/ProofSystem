#include <iostream>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;
using namespace std;

class EthereumKeyGenerator {
public:
    EthereumKeyGenerator() {
        AutoSeededRandomPool prng;
        privateKey.Initialize(prng, ASN1::secp256k1());
        privateKey.MakePublicKey(publicKey);
    }

    ECDSA<ECP, SHA256>::PrivateKey getPrivateKey() const {
        return privateKey;
    }

    ECDSA<ECP, SHA256>::PublicKey getPublicKey() const {
        return publicKey;
    }

    // Add other methods for Ethereum address conversion if needed

private:
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
};
