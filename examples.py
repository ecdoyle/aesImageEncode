from aesImageEncode import *

img = openImage('bean.png')
#img.show()

# ~~~~~~ ECB
def testEncipherSaveEcb(img, k, outputFileName ):
  bytez = image_to_byte_array(img)
  ecb_encipherAndSaveImage(k, bytez, img, outputFileName )

def testDecipherSaveEcb(k,inputFileName, outputFileName ):
  img = openImage(inputFileName)
  bytez = image_to_byte_array(img)
  ecb_decipherAndSaveImage(k, bytez, img, outputFileName)

k = os.urandom(AES.block_size)
testEncipherSaveEcb(img, k, 'ecbEnOutput.png' )
testDecipherSaveEcb(k, 'ecbEnOutput.png', 'ecbDeOutput.png')

# ~~~~~~ CBC
def testEncipherSaveCbc(img, k, ivStr, outputFileName):
  bytez = image_to_byte_array(img)
  iv = binascii.unhexlify(ivStr)
  cbc_encipherAndSaveImage(k, iv, bytez, img, outputFileName)

def testDecipherSaveCbc(k, ivStr, inputFileName, outputFileName):
  img = openImage(inputFileName)
  bytez = image_to_byte_array(img)
  iv = binascii.unhexlify(ivStr)
  cbc_decipherAndSaveImage(k, iv, bytez, img, outputFileName)

k = os.urandom(AES.block_size)
iv = "000102030405060708090a0b0c0d0e0f"

testEncipherSaveCbc(img, k, iv, 'cbcEnOutput.png' )
testDecipherSaveCbc( k, iv, 'cbcEnOutput.png', 'cbcDeOutput.png')

# ~~~~~~ OFB
def testEncipherSaveOfb(img, k, iv, outputFileName):
  bytez = image_to_byte_array(img)
  ofb_encipherAndSaveImage(k, iv, bytez, img, outputFileName)

def testDecipherSaveOfb(k, iv, inputFileName, outputFileName):
  img = openImage(inputFileName)
  bytez = image_to_byte_array(img)
  ofb_decipherAndSaveImage(k, iv, bytez, img, outputFileName)

k = b'andy love simone'
iv = b'Not very random.'

testEncipherSaveOfb(img, k, iv, 'ofbEnOutput.png' )
testDecipherSaveOfb(k, iv, 'ofbEnOutput.png', 'ofbDeOutput.png')


# ~~~~~ Counter
def testEncipherSaveCtr(img, k, counter, outputFileName):
  bytez  = image_to_byte_array(img)
  ctr_encipherAndSaveImage(k, counter, bytez, img, outputFileName )

def testDecipherSaveCtr(k, counter, inputFileName, outputFileName):
  img = openImage(inputFileName)
  bytez = image_to_byte_array(img)
  ctr_decipherAndSaveImage(k, counter, bytez, img, outputFileName )

counter = Counter.new(128, initial_value = int(binascii.hexlify(b'Not very random.'), 16))

testEncipherSaveCtr(img, k, counter, 'ctrEnOutput.png' )
testDecipherSaveCtr(k, counter, 'ctrEnOutput.png','ctrDeOutput.png' )
