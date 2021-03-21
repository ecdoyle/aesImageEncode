from PIL import Image
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
import io,binascii,os,json
from base64 import b64encode


# ~~~~~~ Helper Fxns
# image_to_byte_array - takes Image object and returns bytes in image
# Input:
# image - Image, image to represent as bytes
# Returns:
# bytez - bytes, bytes from image
def image_to_byte_array(image):
  imgByteArr = io.BytesIO()
  image.save(imgByteArr, format=image.format)
  bytez = image.tobytes("raw")
  return bytez

# openImage - takes file and opens
# Input:
# imageFileName - name of file you wish to use
# Returns:
# Python Image object
def openImage(imageFileName):
  return Image.open(imageFileName)

# ~~~~~~ ECB
# ecb_en - encode in ECB mode
# Input:
# k - key
# pt - plaintext in bytes
# Returns:
# ct - ciphertext in bytes
def ecb_en( k, pt):
  cipher =AES.new(k, AES.MODE_ECB)
  ct = cipher.encrypt(pad(pt, AES.block_size))
  return ct

# ecb_de - decode in ECB mode
# Input:
# k - key
# ct - ciphertext in bytes
# Returns:
# pt - plaintext in bytes
def ecb_de( k, ct):
  cipher =AES.new(k, AES.MODE_ECB)
  pt = cipher.decrypt(ct)
  return pt

# ecb_encipherAndSaveImage - encode in ECB mode and save as image
# Input:
# k - key
# pt - plaintext in bytes
# image - image you wish to encode
# outputFileName - name of file you wish to save encoded image as, including file extension
# Returns:
# N/A
def ecb_encipherAndSaveImage(k, pt, image, outputFileName):
  ct = ecb_en(k, pt)
  image = Image.frombytes(image.mode, image.size, ct).save(outputFileName) 

# ecb_decipherAndSaveImage - decipher in ECB mode and save as image
# Input:
# k - key
# ct - ciphertext in bytes
# image - image you wish to decode
# outputFileName - name of file you wish to save decoded image as, including file extension
# Returns:
# N/A
def ecb_decipherAndSaveImage(k, ct, image, outputFileName):
  pt = ecb_de(k, ct)
  image = Image.frombytes(image.mode, image.size, pt).save(outputFileName) 


# ~~~~ CBC
# ecb_en - encode in CBC mode
# Input:
# k - key
# iv - initialization vector
# pt - plaintext in bytes
# Returns:
# ct - ciphertext in bytes
def cbc_en(k, iv, pt):   
  cipher = AES.new(k, AES.MODE_CBC, iv)
  ct = cipher.encrypt(pad(pt, AES.block_size))
  return ct

# ecb_de - decode in CBC mode
# Input:
# k - key
# iv - initialization vector
# ct - ciphertext in bytes
# Returns:
# pt - plaintext in bytes
def cbc_de(k, iv, ct):
  cipher = AES.new(k, AES.MODE_CBC, iv)
  pt = cipher.decrypt(ct)
  return pt

# cbc_encipherAndSaveImage - encode in CBC mode and save as image
# Input:
# k - key
# pt - plaintext in bytes
# image - image you wish to encode
# outputFileName - name of file you wish to save encoded image as, including file extension
# Returns:
# N/A
def cbc_encipherAndSaveImage(k, iv, pt, image, outputFileName):
  ct = cbc_en(k, iv, pt)
  image = Image.frombytes(image.mode, image.size, ct).save(outputFileName) 

# cbc_decipherAndSaveImage - decipher in CBC mode and save as image
# Input:
# k - key
# ct - ciphertext in bytes
# image - image you wish to decode
# outputFileName - name of file you wish to save decoded image as, including file extension
# Returns:
# N/A
def cbc_decipherAndSaveImage(k, iv, ct, image, outputFileName):
  pt = cbc_de(k, iv, ct)
  image = Image.frombytes(image.mode, image.size, pt).save(outputFileName) 


# ~~~~~ OFB
# ecb_en - encode in OFB mode
# Input:
# k - key
# iv - initialization vector
# pt - plaintext in bytes
# Returns:
# ct - ciphertext in bytes
def ofb_en(k, iv, pt):
  cipher = AES.new(k, AES.MODE_OFB, iv)
  ct = cipher.encrypt(pt)
  return ct

# ecb_de - decode in OFB mode
# Input:
# k - key
# iv - initialization vector
# ct - ciphertext in bytes
# Returns:
# pt - plaintext in bytes
def ofb_de(k, iv, ct):
  cipher = AES.new(k, AES.MODE_OFB, iv)
  pt = cipher.decrypt(ct)
  return pt

# ofb_encipherAndSaveImage - encode in OFB mode and save as image
# Input:
# k - key
# pt - plaintext in bytes
# image - image you wish to encode
# outputFileName - name of file you wish to save encoded image as, including file extension
# Returns:
# N/A
def ofb_encipherAndSaveImage(k, iv, pt, image, outputFileName):
  ct = ofb_en(k, iv, pt)
  image = Image.frombytes(image.mode, image.size, ct).save(outputFileName) 

# ofb_decipherAndSaveImage - decipher in OFB mode and save as image
# Input:
# k - key
# ct - ciphertext in bytes
# image - image you wish to decode
# outputFileName - name of file you wish to save decoded image as, including file extension
# Returns:
# N/A
def ofb_decipherAndSaveImage(k, iv, ct, image, outputFileName):
  pt = ofb_de(k, iv, ct)
  image = Image.frombytes(image.mode, image.size, pt).save(outputFileName) 


# ~~~~ CTR
# ctr_en - encode in CTR mode
# Input:
# k - key
# counter - counter for CTR mode
# pt - plaintext in bytes
# Returns:
# ct - ciphertext in bytes
def ctr_en(k, counter, pt):
  cipher = AES.new(k, AES.MODE_CTR, counter=counter)
  ct = cipher.encrypt(pt)
  return ct

# ctr_de - decode in CTR mode
# Input:
# k - key
# counter - counter for CTR mode
# ct - ciphertext in bytes
# Returns:
# pt - plaintext in bytes
def ctr_de(k, counter, ct):
  cipher = AES.new(k, AES.MODE_CTR, counter=counter)
  pt = cipher.decrypt(ct)
  return pt

# ctr_encipherAndSaveImage - encode in CTR mode and save as image
# Input:
# k - key
# counter - counter for CTR mode
# pt - plaintext in bytes
# image - image you wish to encode
# outputFileName - name of file you wish to save encoded image as, including file extension
# Returns:
# N/A
def ctr_encipherAndSaveImage(k, counter, pt, image, outputFileName):
  ct = ctr_en(k, counter, pt)
  image = Image.frombytes(image.mode, image.size, ct).save(outputFileName)

# ctr_decipherAndSaveImage - decipher in CTR mode and save as image
# Input:
# k - key
# counter - counter for CTR mode
# ct - ciphertext in bytes
# image - image you wish to decode
# outputFileName - name of file you wish to save decoded image as, including file extension
# Returns:
# N/A
def ctr_decipherAndSaveImage(k, counter, ct, image, outputFileName):
  pt = ctr_de(k, counter, ct)
  image = Image.frombytes(image.mode, image.size, pt).save(outputFileName) 
