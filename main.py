# https://cryptography.io/en/latest/

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def main():

  key_size = 1024
  
  msg = 'testando msg'

  #Key generation
  N, e, d, private_key = RSAGen(key_size)

  #Hashing da msg
  hash_sha3 = HashSHA3(msg.encode('utf-8'))

  #Assinatura da mensagem
  signature = Enc(private_key.public_key(), hash_sha3)

  #Decifração da assinatura
  rcv_hash = Dec(private_key, signature)

  #Verificação
  rcv_msg = msg
  new_hash = HashSHA3(rcv_msg.encode('utf-8'))

  if(new_hash == rcv_hash):
    print("Assinatura correta.")
  
  else:
    print("Assinatura incorreta!!! Documento modificado ou de outro remetente.")


  print("OK")

  #print(rcv_hash)
  #print(new_hash)

  #print(signature)

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

## Faz com public_key pois modulo nao suporta assinatura com OAEP
def Enc(public_key, hash_sha3):

  #Usando sha2-256
  ciphertext = public_key.encrypt(hash_sha3, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

  return ciphertext

## Faz com private_key pois modulo nao suporta assinatura com OAEP
def Dec(private_key, ciphertext):

  hash_sha3 = private_key.decrypt(ciphertext, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

  return hash_sha3

#SHA3 com 256 bit result/digest
def HashSHA3(msg_bytes):

  hash_sha3 = hashes.Hash(hashes.SHA3_256())
  hash_sha3.update(msg_bytes)
  digest = hash_sha3.finalize()

  return digest

if __name__ == "__main__":
  main()