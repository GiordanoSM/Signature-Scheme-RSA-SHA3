# https://cryptography.io/en/latest/

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def main():

  key_size = 1024
  
  msg = 'testando msg'

  N, e, d, private_key = RSAGen(key_size)

  ciphertext = Enc(private_key, msg)

  print("OK")

  #print(ciphertext)

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

  return public_numbers.n, public_numbers.e, private_numbers.d, private_key

def Enc(private_key, msg):

  public_key = private_key.public_key()

  #Usando sha2
  ciphertext = public_key.encrypt(msg.encode('utf-8'), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

  return ciphertext

if __name__ == "__main__":
  main()