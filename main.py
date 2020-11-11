from cryptography.hazmat.primitives.asymmetric import rsa

def main():

  public_e = 65537

  key_size = 1024

  private_key = rsa.generate_private_key(public_e, key_size)

  print(isinstance(private_key, rsa.RSAPrivateKey))

  public_key = 1


if __name__ == "__main__":
  main()