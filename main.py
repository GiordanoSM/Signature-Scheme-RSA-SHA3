# https://cryptography.io/en/latest/

import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import exceptions

INCORRECT = False

def main(arguments):

  sk_file = 'key.key'
  pk_file = 'public_key.key'
  operation = arguments[1].lower()

  #-------------------------Key generation------------------------------

  if operation == 'genrsa':

    key_size = 1024

    N, e, d, private_key = RSAGen(key_size)

    public_key = private_key.public_key()

    #Arquivo com private key
    with open(sk_file, 'wb') as f:
      pem = private_key.private_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm= serialization.NoEncryption()
        )
      f.write(pem)
    
    #Arquivo com public key
    with open(pk_file, 'wb') as f:
      pem = public_key.public_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PublicFormat.SubjectPublicKeyInfo
      )
      f.write(pem)

  #-------------------------------File signing----------------------------------
  elif operation == 'sign' or operation == 'verify':

    if len(arguments) < 3:
      print('ERRO: Indique o nome do arquivo a ser assinado.')

    else:
      input_file = arguments[2]

      #Nome do arquivo com chave privada informado
      if len(arguments) >= 4:
        sk_file = arguments[3]

      #Lendo arquivo a ser assinado
      try:

        with open(input_file, 'rb') as f:
          msg = f.read()
      
      except IOError:
        print("ERRO: Arquivo não existente!")
        exit()

      finally:
        pass

      #Load da chave privada
      try:
        with open(sk_file, 'rb') as key_file:
          private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
          )

      except IOError:
        print("ERRO: Arquivo da chave privada não existente!")
        exit()

      except ValueError:
        print("ERRO: Estrutura da chave privada não pode ser descodificada!")
        exit()

      except exceptions.UnsupportedAlgorithm:
        print("ERRO: Tipo de chave privada não suportada!")
        exit()

      finally:
        pass

      #Load da chave pública
      try:
        with open(pk_file, 'rb') as key_file:
          public_key = serialization.load_pem_public_key(
            key_file.read(),
          )

      except IOError:
        print("ERRO: Arquivo da chave pública não existente!")
        exit()

      except ValueError:
        print("ERRO: Estrutura da chave pública não pode ser descodificada!")
        exit()

      except exceptions.UnsupportedAlgorithm:
        print("ERRO: Tipo de chave pública não suportada!")
        exit()

      finally:
        pass
    

      #Processo de assinatura
      signed_msg = Sign(public_key, msg)

      #Envio da mensagem assinada
      status = Send(private_key, signed_msg)
 
  else:
    print('ERRO: Operação desejada não definida.')

  print("OK")

  #print(signed_msg)

  '''for i in [N, e, d]:
    print(i)'''

#--------------------------------------------Funções utilizadas------------------------------------

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

#Realizar a assinantura (deveria ser realizada pela key privada)
def Sign(public_key, message):

  #Hashing da msg
  msg_hash = HashSHA3(message)

  #Geração da assinatura
  signature = Enc(public_key, msg_hash)

  return [signature, message]

#Verificação da assinatura (deveria ser realizada pela key publica)
def Verify(private_key, signed_msg):

  signature = signed_msg[0]
  rcv_msg = signed_msg[1]

  #Decifração da assinatura
  rcv_hash = Dec(private_key, signature)

  #Verificação
  new_hash = HashSHA3(rcv_msg)

  if(new_hash == rcv_hash):
    print("Assinatura correta.")
    return True
  
  else:
    print("Assinatura incorreta!!! Documento modificado ou de outro remetente.")
    return False


#Idealmente o destinatario ja deveria saber a key publica
def Send(private_key, signed_msg):

  msg = signed_msg[1]

  #Modifica a mensagem caso requerido (INCORRECT = True)
  if len(msg) > 0 and INCORRECT:
    msg = msg.swapcase()

  signed_msg[1] = msg

  #Passa a mensagem para o destinatário
  return Verify(private_key, signed_msg)

if __name__ == "__main__":

  if len(sys.argv) < 2:
    print("ERRO: Por favor, indique a operação a ser realizada.") #falar quando a operação n definida

  else:
    main(sys.argv)