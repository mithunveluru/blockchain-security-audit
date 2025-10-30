from Crypto.PublicKey import RSA

def generate_rsa_keypair(key_size=2048, priv_file='device_priv.pem', pub_file='device_pub.pem'):
    """
    Generate RSA Key Pair and save to files.
    :param key_size: Size of key in bits (2048 recommended)
    :param priv_file: Output private key filename
    :param pub_file: Output public key filename
    """
    key = RSA.generate(key_size)
    
    private_key = key.export_key()
    with open(priv_file, 'wb') as f:
        f.write(private_key)
    print(f"Private key saved to {priv_file}")
    
    public_key = key.publickey().export_key()
    with open(pub_file, 'wb') as f:
        f.write(public_key)
    print(f"Public key saved to {pub_file}")

if __name__ == "__main__":
    generate_rsa_keypair()
