import hashlib

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .?,!;:@#$%&*[{()}]"+-_=1234567890/\''
character_list = [i for i in characters]
character_code = [i for i in range(1,len(characters)+1)]
value_table = {k:v for k,v in zip(character_code,character_list)}
value_table_search = {k:v for k,v in zip(character_list,character_code)}

def encrypt(plain_text:str,key:str)->str:
    cipher_text = ''
    secret_key = hashlib.blake2b(str(key).encode(encoding='ascii')).hexdigest()
    if len(secret_key) < len(plain_text):
      secret_key = secret_key.zfill(len(plain_text))
    for c,d in zip(plain_text,secret_key):
      index = int(value_table_search[c])+int(value_table_search[d]) 
      if index > len(value_table):
        index -= len(value_table)
      cipher_text += value_table[index]
    return cipher_text

def decrypt(encrypted_text:str,key:str)->str:
    decrypted_text = ''
    secret_key = hashlib.blake2b(str(key).encode(encoding='ascii')).hexdigest()
    if len(encrypted_text) > len(secret_key):
      secret_key = secret_key.zfill(len(encrypted_text))
    for c,d in zip(encrypted_text,secret_key):
        index = int(value_table_search[c])-int(value_table_search[d])
        if index < 1:
            index += len(value_table)
        decrypted_text += value_table[index]
    return decrypted_text
