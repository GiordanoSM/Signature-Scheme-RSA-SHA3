# Giordano Süffert Monteiro - 17/0011160
# Última modificação: 06/12/20

# https://cryptography.io/en/latest/

# Execução na linha de comando: python3 main.py arg1 arg2 arg3
# Python 3.7.1

import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import exceptions


def main(arguments):

  sk_file = 'key.key'
  operation = arguments[1].lower()

  #-------------------------Key generation------------------------------

  if operation == 'genrsa':

    pk_file = 'public_key.key'

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

    print('Chaves criadas com sucesso! Arquivos: {} e {}'.format(sk_file, pk_file))

  #-------------------------------File signing----------------------------------
  elif operation == 'sign':

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
    

      #Processo de assinatura
      signed_msg = Sign(private_key, msg)

      public_key = private_key.public_key()

      #Public key dump
      public_key_dump = public_key.public_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PublicFormat.SubjectPublicKeyInfo
      )

      #Formatação do arquivo
      formatted_signed_msg = Format(public_key_dump, signed_msg[0], signed_msg[1], input_file)

      extension_i = input_file.rfind('.')
  
      #Removendo a extensão do nome do arquivo
      if extension_i != -1:
        input_file_we = input_file[:extension_i]

      else:
        input_file_we = input_file

      formatted_file_name = 'signed_'+input_file_we

      #Criação do arquivo formatado com mensagem assinada
      with open(formatted_file_name, 'wb') as f:
        f.write(formatted_signed_msg)

      print('Assinado com sucesso. Criado arquivo: {}'.format(formatted_file_name))

  #-------------------------------File verification----------------------------------
  elif operation == 'verify':

    #Precisa do arquivo assinado
    if len(arguments) < 3:
      print('ERRO: Indique o nome do arquivo assinado.')

    else:

      formatted_file_name = arguments[2]

      #Se existo o terceiro argumento, é o nome do arquivo com a chave
      if len(arguments) >= 4:

        have_pk_file = True

        #Load da chave pública
        try:
          with open(arguments[3], 'rb') as key_file:
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

      else:
        have_pk_file = False

      #Leitura do arquivo formatado
      try:
        with open(formatted_file_name, 'rb') as f:
          formatted_signed_msg = f.read()
      
      except IOError:
        print("ERRO: Arquivo não existente!")
        exit()

      finally:
        pass

      #Parsing do arquivo assinado
      header_dict, public_key_2, signed_msg = Parsing(formatted_signed_msg, have_pk_file)
 
      if not have_pk_file: public_key = public_key_2

      status = Verify(public_key, signed_msg, header_dict)

      keys = header_dict.keys()

      #Criando arquivo com mensagem original
      if status:
        if b'filename' in keys:
          file_name = header_dict[b'filename'].decode()
        else:
          file_name = 'message'

        with open('new_'+file_name, 'wb') as f:
          f.write(signed_msg[1])

        print('Criado arquivo com a mensagem: {}'.format('new_'+file_name))

  #-------------------------------Sem Operação----------------------------------
  else:
    print('ERRO: Operação desejada não definida.')








#--------------------------------------------Funções utilizadas------------------------------------

#-------------------------Geração de chave
def RSAGen(key_size): 

  public_e = 65537

  private_key = rsa.generate_private_key(public_e, key_size)

  private_numbers = private_key.private_numbers()

  public_key = private_key.public_key()

  public_numbers = public_key.public_numbers()

  return public_numbers.n, public_numbers.e, private_numbers.d, private_key

#-------------------------SHA3 com 256 bit result/digest
def HashSHA3(msg_bytes):

  hash_sha3 = hashes.Hash(hashes.SHA3_256())
  hash_sha3.update(msg_bytes)
  digest = hash_sha3.finalize()

  return digest

#-------------------------Realizar a assinatura
def Sign(private_key, message):

  #Hashing da msg
  msg_hash = HashSHA3(message)

  #Geração da assinatura
  signature = private_key.sign(msg_hash, 
    padding.PSS(mgf= padding.MGF1(hashes.SHA3_256()), salt_length= padding.PSS.MAX_LENGTH),
    hashes.SHA3_256())

  return [signature, message]

#-------------------------Verificação da assinatura
#Requer header com componentes esperadas
#Realizando verificação somente do algoritmo, padding e hash usados na assinatura Sign()
def Verify(public_key, signed_msg, header_dict):

  signature = signed_msg[0]
  rcv_msg = signed_msg[1]

  #Verificação

  if header_dict[b'protocol'] != b'RSA' or header_dict[b'padding'] != b'PSS' or header_dict[b'hash_type'] != b'SHA3_256':
    print('ERRO: Configuração de protocolo, padding e hash não suportadas. Verificação não foi possível.')
    exit()

  new_hash = HashSHA3(rcv_msg)

  try:
    public_key.verify(signature, new_hash, 
      padding.PSS(mgf= padding.MGF1(hashes.SHA3_256()), salt_length= padding.PSS.MAX_LENGTH), 
      hashes.SHA3_256())

  except exceptions.InvalidSignature:
    print("Assinatura incorreta!!! Documento modificado ou de outro remetente.")
    return False

  finally:
    pass
  
  print("Assinatura correta!")
  return True

#--------------------------------Formatação: Baseada na formatação S/MIME
def Format(public_key_dump, signature, message, msg_file_name):

  protocol = b'RSA'
  padding = b'PSS'
  hash_type = b'SHA3_256'
  boundary = b'------714A286D976BF3E58D9D671E37CBCF7C'

  header = b'protocol= %(protocol)b;padding= %(padding)b;hash_type= %(hash_type)b;boundary= %(boundary)b;filename= %(filename)b' %{
    b'protocol': protocol, b'padding': padding, b'hash_type': hash_type, b'boundary': boundary, b'filename': msg_file_name.encode()}

  header = header + b'\n'

  signature_block = b'%(boundary)b%(signature)b' %{b'boundary': boundary, b'signature': signature}

  message_block = b'%(boundary)b%(message)b' %{b'boundary': boundary, b'message': message}

  public_key_block = b'%(boundary)b%(public_key)b' %{b'boundary': boundary, b'public_key': public_key_dump}

  formatted_signed_msg = header + signature_block + message_block + public_key_block

  return formatted_signed_msg

#--------------------------------Parsing: assume existência de \n no fim do header
def Parsing(formatted_msg, have_pk_file):
  
  divided = formatted_msg.partition(b'\n')

  header = divided[0]

  data = divided[2]

  header_div = header.split(b';')

  header_dict = {}

  public_key = b''

  for attr in header_div:
    attr_div = attr.split(b'= ')

    #Verificando a existencia de '= '
    if (len(attr_div)<2):
      print('ERRO: Valor de atributo não presente para parsing')
      exit()
    
    header_dict[attr_div[0]] = attr_div[1]

  keys = header_dict.keys()

  #Verificando a existencia de todos os campos necessários
  if not ((b'protocol' in keys) and (b'padding' in keys) and (b'hash_type' in keys) and (b'boundary' in keys)):
    print('ERRO: Atributo necessário não presente para parsing')
    exit()

  data_div = data.split(header_dict[b'boundary'])

  #Verificando a existencia de campos com a chave pública, assinatura e mensagem. Esperado primeiro elemento vazio.
  if len(data_div) < 3 or (len(data_div) < 4 and not have_pk_file) :
    print('ERRO: Informação faltante no arquivo, erro na formatação')
    exit()

  #Load da assinatura
  signature = data_div[1]

  #Load da mensagem
  message = data_div[2]

  if not have_pk_file:

    #Load da chave pública
    try:
      public_key = serialization.load_pem_public_key(data_div[3])

    except ValueError:
      print("ERRO: Estrutura da chave pública não pode ser descodificada!")
      exit()

    except exceptions.UnsupportedAlgorithm:
      print("ERRO: Tipo de chave pública não suportada!")
      exit()

    finally:
      pass

  return header_dict, public_key, [signature, message]

#-------------------------------------------------------------

if __name__ == "__main__":

  if len(sys.argv) < 2:
    print("ERRO: Por favor, indique a operação a ser realizada.")

  else:
    main(sys.argv)