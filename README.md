# hybrid_encryption

This project is based on dual encryption for an image

 - first we encrypt the image using aes 
 - then save the encrypted file as a .dat file 
 - the aes key is then also encrypted via ecc 
 


 Instructions
  
gcc aes.c -o aes_enc -lcrypto

./aes_enc <imagename>

 ps: use png 
 
gcc aes_dec.c -o aes_dec -lcrypto
 
 ./aes_dec <encrypted file>
 
key 

after decryption change the image extension to the orginal or use png images

