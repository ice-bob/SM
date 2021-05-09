'''
@author     ice-bob
@copyright  MIT license

SM3 cryptographic hash algorithm
SM3 standards:http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html

'''

class SM3(object):
    """SM3 cryptographic hash algorithm"""

    __state = []      # intermediate digest state
    __input = ''      # data
    __output = 0      # hash value

    def __init__(self,input):
        '''Initial variable preparation '''
        self.__state = [
            0x7380166F,
            0x4914B2B9,
            0x172442D7,
            0xDA8A0600,
            0xA96F30BC,
            0x163138AA,
            0xE38DEE4D,
            0xB0FB0E4E
            ]
        self.__input = input
    
    def __LeftRotate(self,x,i):
        '''Left rotate i bits'''
        return (x << i & 0xffffffff) | (x >> (32-i) & 0xffffffff)

    
    def __FF(self,x,y,z,i):
        if i >= 0 and i <= 15:
            return x^y^z
        if i >= 16 and i <= 63:
            return (x & y) | (x & z) | (y & z)

    def __GG(self,x,y,z,i):
        if i >= 0 and i <= 15:
            return x^y^z
        if i >= 16 and i <= 63:
            return (x & y) | (~x & z) 

    def __P0(self,x):
        return x ^ \
               self.__LeftRotate(x,9) ^ \
               self.__LeftRotate(x,17)

    def __P1(self,x):
        return x ^ \
               self.__LeftRotate(x,15) ^ \
               self.__LeftRotate(x,23)

    def __process(self,data):
        '''
        data    512-bit block, int

        Processing message block
        '''
        T = []
        W = [] 
        W_ = []

        for i in range(0,16):
            T.append(0x79CC4519)
        for i in range(16,64):
            T.append(0x7A879D8A)

        for i in range(0,16):
            W.append(data >> (480-(i*32)) & 0xffffffff)

        for i in range(16,68):
            W.append(self.__P1(W[i-16] ^ W[i-9] ^ self.__LeftRotate(W[i-3],15)) ^\
                     self.__LeftRotate(W[i-13],7) ^\
                     W[i-6])

        for i in range(0,64):
            W_.append(W[i] ^ W[i+4])



        A = self.__state[0]
        B = self.__state[1]
        C = self.__state[2]
        D = self.__state[3]
        E = self.__state[4]
        F = self.__state[5]
        G = self.__state[6]
        H = self.__state[7]

        SS1 = 0
        SS2 = 0
        TT1 = 0
        TT2 = 0
        for i in range(0,64):
            SS1 = self.__LeftRotate(((self.__LeftRotate(A,12) + E + self.__LeftRotate(T[i],i % 32)) & 0xffffffff),7)
            SS2 = SS1 ^ self.__LeftRotate(A,12)
            TT1 = (self.__FF(A,B,C,i) + D + SS2 + W_[i]) & 0xffffffff
            TT2 = (self.__GG(E,F,G,i) + H + SS1 + W[i]) & 0xffffffff
            D = C
            C = self.__LeftRotate(B,9)
            B = A
            A = TT1
            H = G
            G = self.__LeftRotate(F,19)
            F = E
            E = self.__P0(TT2)

        self.__state[0] = self.__state[0] ^ A
        self.__state[1] = self.__state[1] ^ B
        self.__state[2] = self.__state[2] ^ C
        self.__state[3] = self.__state[3] ^ D
        self.__state[4] = self.__state[4] ^ E
        self.__state[5] = self.__state[5] ^ F
        self.__state[6] = self.__state[6] ^ G
        self.__state[7] = self.__state[7] ^ H



    def update(self):
        '''
        padding and processing blocks
        
        str and int -> types -> int
        '''
        if isinstance(self.__input,str):
            input_bytes = self.__input.encode()
        elif isinstance(self.__input,int):
            input_bytes = self.__input.to_bytes(length=self.__input.bit_length()//8+1,byteorder='big',signed=False)


        bs = len(input_bytes) * 8 // 512
        for i in range(bs):               #first n-1 blocks
            self.__process(int.from_bytes(input_bytes[i*64:i*64+64],byteorder='big', signed=False))
            i += 1

        end_len = len(input_bytes) * 8 - bs * 512
        if end_len < 448:                 #n-th block after padding 
            end = int.from_bytes(input_bytes[bs*64:],byteorder='big', signed=False)
            end = end << 1 | 1
            end = end << (447 - end_len)
            end = end << 64 | (end_len & 0xffffffffffffffff)
            self.__process(end)
        elif end_len >= 448:             #n-th and (n+1)-th blocks after padding
            end = int.from_bytes(input_bytes[bs*64:],byteorder='big', signed=False)
            end = end << 1 | 1
            end = end << (511 - end_len)
            self.__process(end)
            self.__process(end_len & 0xffffffffffffffff)
        
        self.__hash_256()
        return self.__output

    def __hash_256(self):
        '''Concatenated hash value'''
        for v in self.__state:
            self.__output = self.__output << 32 | v
            





            
