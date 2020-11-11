# https://cryptography.io/en/latest/

from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():

  key_size = 1024
  
  N, e, d = RSAGen(key_size)

  print("OK")

  '''for i in [N, e, d]:
    print(i)'''

  
def RSAGen(key_size): 

  public_e = 65537

  private_key = rsa.generate_private_key(public_e, key_size)

  if not(isinstance(private_key, rsa.RSAPrivateKeyWithSerialization)) or private_key.key_size != key_size:
    print("Erro na obtenção da chave privada.")

  private_numbers = private_key.private_numbers()

  public_key = private_key.public_key()

  public_numbers = public_key.public_numbers()

  if public_e != public_numbers.e:
    print("Erro na definição do expoente público.") 

  return public_numbers.n, public_numbers.e, private_numbers.d

if __name__ == "__main__":
  main()