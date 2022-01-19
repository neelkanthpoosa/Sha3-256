import re
import numpy as np
import math
import random

class sha3:

    def hash256(self, message):
        return self.keccak1600(1088, 512, message)
    
    def keccak1600(self, r, c, M):
        l = c//2

        msg = ''

        if self.opt['msgFormat'] == 'string':
            msg = self.utf8Encoding(M)
            
        elif self.opt['msgFormat'] == 'hex-bytes':
            msg = self.hexToString(M)

        state = [[0 for j in range(5)] for i in range(5)]

        q = (r//8) - len(msg)%(r//8)

        if q == 1:
            msg += chr(0x81) if self.opt['padding'] == 'keccak' else chr(0x86)
        else:
            msg += chr(0x01) if self.opt['padding'] == 'keccak' else chr(0x06)
            for i in range(q-2):
                msg += chr(0x00)
            msg += chr(0x80)

        w = 64
        blocksize = (r/w) * 8

        for i in range(0,len(msg), int(blocksize)):
            for j in range(0, r//w):
                i64 = ord(msg[i+j*8+0])<<0 + (ord(msg[i+j*8+1])<< 8) + (ord(msg[i+j*8+2])<<16) + (ord(msg[i+j*8+3])<<24) + (ord(msg[i+j*8+4])<<32) + (ord(msg[i+j*8+5])<<40) + (ord(msg[i+j*8+6])<<48) + (ord(msg[i+j*8+7])<<56)
                x = j % 5
                y = math.floor(j/5)
                state[x][y] = state[x][y] ^ i64
            # print('here')
            self.keccak_f_1600(state)
        
        state = np.array([[''.join(re.findall('.{2}', format(int(lane),'x').zfill(16))[::-1]) for lane in plane] for plane in state]).T.tolist()
        md = ''.join([''.join(plane) for plane in state])[:l//4]

        return md

    def keccak_f_1600(self, a):
        nRounds = 24

        RC = [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ]

        for r in range(nRounds):
            print(r)
            C, D = [0]*5, [0]*5
            for x in range(5):
                C[x] = a[x][0]
                for y in range(1, 5):
                    C[x] = C[x] ^ a[x][y]

            for x in range(5):
                D[x] = C[(x+4)%5] ^ self.ROT(C[(x+1)%5], 1)
                for y in range(5):
                    a[x][y] = a[x][y] ^ D[x]

            # ρ + π
            x, y = 1, 0
            current = a[x][y]
            for t in range(24):
                X, Y = y, (2*x + 3*y)%5
                tmp = a[X][Y]
                a[X][Y] = self.ROT(current, ((t+1)*(t+2)/2)%64)
                current = tmp
                x, y = X, Y

            # χ
            for y in range(5):
                C = [0]*5
                for x in range(5):
                    C[x] = a[x][y]
                for x in range(5):
                    a[x][y] = (C[x] ^ ((~C[(x+1)%5]) & C[(x+2)%5]))

            a[0][0] = (a[0][0] ^ RC[r])

    def ROT(self, a, d):
        return int(a) << int(d) | int(a) >> (64-int(d))

    def transpose(self, l):
        return list(map(list, zip(*l)))


    def utf8Encoding(self, Str):
        try:
            s = ''.join([chr(c) for c in Str])
            return s
        except:
            return Str

    def hexToString(self, hexStr):
        s = hexStr.replace(' ', '')
        return ''.join(list(map(lambda x: chr(int(x,16)), re.findall('.{2}',s)))) if s != '' else ''

userList={}

print("For input: abc")
sha3 = sha3()
input='abc'
print(sha3.hash256(input))
