import numpy as np
from gf_arithmetic import matrix_multiply_gf2, invert_matrix_gf2

def decrypt(ciphertext, private_key):
    """
    Decrypt a McEliece ciphertext using the private key.
    :param ciphertext: A binary numpy array of length n.
    :param private_key: Dictionary containing 'S', 'G', 'P', and 'goppa_code'.
    :return: The decrypted message as a binary numpy array.
    """
    S = private_key['S']
    P = private_key['P']
    goppa_code = private_key['goppa_code']
    
    # remove the permutation by multiplying with P^-1
    P_inv = P.T
    c_prime = matrix_multiply_gf2(ciphertext.reshape(1, -1), P_inv).flatten()

    # 2. Use the Goppa code's decoding algorithm to remove the error added during encryption . 
   
    corrected_codeword = goppa_code.decode(c_prime)
    
    
    k, n = goppa_code.G.shape
    
    # try to find G as if it were systematic
    
    cols = list(range(n-k, n))

    try:
        G_sub = goppa_code.G[:, cols]
        G_sub_inv = invert_matrix_gf2(G_sub)
    except ValueError:
       
        cols = []
        for i in range(n):
            cols.append(i)
         
            pass
            
      # if the G not systematic .
        from gf_arithmetic import rref_gf2
        rref_G = rref_gf2(goppa_code.G)
        cols = []
        r = 0
        for c in range(n):
            if r >= k: break
            if rref_G[r, c] == 1:
                cols.append(c)
                r += 1
                
        G_sub = goppa_code.G[:, cols]
        G_sub_inv = invert_matrix_gf2(G_sub)

    c_sub = corrected_codeword[cols]
    m_prime = matrix_multiply_gf2(c_sub.reshape(1, -1), G_sub_inv).flatten()
    
    # 3. m = m' * S^-1
    S_inv = invert_matrix_gf2(S)
    message = matrix_multiply_gf2(m_prime.reshape(1, -1), S_inv).flatten()
    
    return message
