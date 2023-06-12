import numpy as np
import math as math


def pad(M,n):
    m = '0x'
    for i in M:
        m += hexa_2(i)[2:]
    tmp = int((len(m[2:])*8)/2)
    m += '80'
    i = int(len(m[2:])/2)
    while i%n != n-8:
        m += '00'
        i+=1
    m += barray(tmp,8)[2:]
    return m
def barray(a,b):
    a = hex(a)[2:]
    return '0x'+(2*b-len(a))*'0'+ a
def Message2State(M):
    M = pad(M,32)[2:]
    K = []
    for i in range(int(len(M)/32)):
        K.append('0x'+M[i*32:(i+1)*32])
    for (i1,i2) in enumerate(K):
        tmp = []
        for j in range(4):
            tmp.append('0x'+i2[2:][8*j:8*(j+1)])
        K[i1] = tmp
    return K

# =============================================================================
#                                   CONSTANTS
# =============================================================================

Nb = 4 
Nk = 4 #for AES 128
Nr = 10 #for AES 128


K = 0
state = 0


sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], 
		[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0], 
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], 
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75], 
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84], 
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf], 
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8], 
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2], 
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73], 
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb], 
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79], 
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08], 
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], 
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e], 
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], 
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]
		
invsbox = [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb], 
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb], 
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e], 
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25], 
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92], 
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84], 
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06], 
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b], 
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73], 
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e], 
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b], 
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4], 
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f], 
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef], 
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61], 
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]
		
rcon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 
        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]

mixVars = [0x02030101, 0x01020301, 0x01010203, 0x03010102]

invMixVars = [0x0e0b0d09, 0x090e0b0d, 0x0d090e0b, 0x0b0d090e]


# =============================================================================
#                           AUXILIARY FUNCTIONS
# =============================================================================
def RotateLeft(aa,nn):     #Rotates left
    aa = aa & 0xFFFFFFFF
    X = ((aa << nn) | (aa >> (32 - nn))) & 0xFFFFFFFF
    return hexa_8(X)
def hexa_2(a):
    if len(hex(a))%2!=0:
        return '0x0'+hex(a)[2:]
    else:
        return hex(a)
def hexa_8(a):            #Returns the hexadecimal value of a with an even number of values (adds zeros to the "left" so that it has 8*k bits)
    if len(hex(a)[2:]) == 8:
        return hex(a)
    else:
        return '0x' + '0'*(8-len(hex(a)[2:])%8) + hex(a)[2:]  
def int2str(A):         #Transforms a list of integers into a list of hexadecimal values (in str)
    if type(A[0]) == int:
        K = []
        for i in A:
            K.append(hexa_8(i))
        return K
    else:
        return A
def str2int(A):         #Inverse of int2str
    if type(A[0]) == str:
        K = []
        for i in A:
            K.append(int(i,16))
        return K
    else:
        return A
def list2matrix(A):         #Transforms a list of numbers into a list of lists (matrix)
    A = int2str(A)
    tmp = []
    for i in range(len(A)):
        tmp.append([])
        for j in range(0,len(A[i][2:]),2):
            tmp[-1].append(int(A[i][2:][j:j+2],16))
    return tmp
def matmul(A,B):            #Multiplies 2 matrices (A and B)
    result = []
    for i in range(len(A)):
        result.append([])
        for j in range(len(B[0])):
            result[-1].append(0)
            for k in range(len(A[0])):
                result[i][j] = (result[i][j] ^ fastMul(A[i][k],B[k][j]))
    return result

def transpose(inp):         #Transposes a list of numbers
    inp = int2str(inp)
    tmp = []
    for i in range(len(inp)):
        tmp.append([])
        for j in range(0,len(inp[i][2:]),2):
            tmp[-1].append(inp[i][2:][j:j+2])
    tmp = np.matrix(tmp).transpose().tolist()
    for i in range(len(tmp)):
        tmp[i] = '0x'+''.join(tmp[i])
    return tmp
#def fastMul(a,e):           #Multiplies two numbers under the Galois field of 2^8
#    tmp = 2
#    base = a
#    while tmp <= e:
#        if ( ((a >> 7) & 0xFF) == 0x01):
#            a = ((a << 1) & 0xFF) ^ 0x1b
#        else:
#            a = ((a << 1) & 0xFF)
#        tmp *= 2
#    tmp = tmp/2
#    while tmp < e:
#        a = a ^ base
#        tmp += 1
#    return a & 0xFF


def xTimes(a, e):
        while (e != 0x01):
            sign = (a >> 7) & 0x01
            a = (a << 1) & 0xFF
            if (sign == 1):
                a = a ^ 0x1b
            e = e//2
        return a
    
def fastMul(a, e):
    temp = 0x00
    for i in range(7,0,-1):
        if (((e >> i) & 0x01) == 1):
            temp = temp ^ xTimes(a, math.pow(2, i))
    if (e % 2 == 1):
        temp = temp ^ a
    return temp


# =============================================================================
#                           MAIN FUNCTIONS
# =============================================================================
    
#1st Function (SubWords)
def SubWord(State):
    if type(State) == int:
        State = hexa_8(State)
    if len(State)%2 != 0:
        State = '0x0' + State[2:]
    tmp = '0x'
    for i in range(0,len(State[2:]),2):
        (a, b) = (State[2:][i], State[2:][i+1])
        (a, b) = (int(a,16),int(b,16))
        tmp += hexa_2(sbox[a][b])[2:]
    return tmp
def InvSubWord(State):
    if type(State) == int:
        State = hexa_8(State)
    if len(State)%2 != 0:
        State = '0x0' + State[2:]
    tmp = '0x'
    for i in range(0,len(State[2:]),2):
        (a, b) = (State[2:][i], State[2:][i+1])
        (a, b) = (int(a,16),int(b,16))
        tmp += hexa_2(invsbox[a][b])[2:]
    return tmp

def SubWords(State):
    State = int2str(State)
    for (a,b) in enumerate(State):
        State[a] = SubWord(b)
    return State
def InvSubWords(State):
    State = int2str(State)
    for (a,b) in enumerate(State):
        State[a] = InvSubWord(b)
    return State


#2nd Function (ExpandKey)
def ExpandKey(K):
    K = str2int(K)
    for i in range(Nk,(Nr+1)*Nb):
        tmp = K[-1]
        if i % Nk == 0:
            tmp = int(SubWord(RotateLeft(tmp,8)),16) ^ rcon[int(i/Nk)-1]
        else:
            if (Nk > 6) and (i % Nk) == 4:
                tmp = int(SubWord(tmp),16)
        K.append(K[i-Nk]^tmp)
    return K

#3rd function
def AddRoundKey(State,key):
    State = int2str(State)
    key = int2str(key)
    tmp = []
    for (a,b) in enumerate(State):
        tmp.append(int(b,16)^int(key[a],16))
    for i in range(len(tmp)):
        tmp[i] = hexa_8(tmp[i])
    return tmp


#4th function
def ShiftRow(State):
    State = int2str(State)
    State = transpose(State)
    tmp = []
    for i in range(len(State)):
        tmp.append([])
        for j in range(0,len(State[i][2:]),2):
            tmp[-1].append(State[i][2:][j:j+2])
    for i in range(len(tmp)):
        tmp[i] = tmp[i][i:]+tmp[i][:i]
    tmp = np.matrix(tmp).transpose().tolist()
    for i in range(len(tmp)):
        tmp[i] = '0x' + ''.join(tmp[i])
    return tmp

def InvShiftRow(State):
    State = int2str(State)
    State = transpose(State)
    tmp = []
    for i in range(len(State)):
        tmp.append([])
        for j in range(0,len(State[i][2:]),2):
            tmp[-1].append(State[i][2:][j:j+2])
    for i in range(len(tmp)):
        tmp[i] =  tmp[i][-i:] + tmp[i][:-i]
    tmp = np.matrix(tmp).transpose().tolist()
    for i in range(len(tmp)):
        tmp[i] = '0x' + ''.join(tmp[i])
    return tmp

#5th function
def MixingColumns(State):
    State = int2str(State)
    mix = int2str(mixVars)
    State = transpose(State)
    State = list2matrix(State)
    mixy = list2matrix(mix)
    Fstate = matmul(mixy,State)
    for i in range(len(Fstate)):
        for j in range(len(Fstate)):
            Fstate[i][j] = hexa_2(Fstate[i][j])[2:] 
    Fstate = np.matrix(Fstate).transpose().tolist()
    for i in range(len(Fstate)):
        Fstate[i] = '0x' + ''.join(Fstate[i])
    return Fstate

def InvMixingColumns(State):
    State = int2str(State)
    mix = int2str(invMixVars)
    State = transpose(State)
    State = list2matrix(State)
    mixy = list2matrix(mix)
    Fstate = matmul(mixy,State)
    for i in range(len(Fstate)):
        for j in range(len(Fstate)):
            Fstate[i][j] = hexa_2(Fstate[i][j])[2:] 
    Fstate = np.matrix(Fstate).transpose().tolist()
    for i in range(len(Fstate)):
        Fstate[i] = '0x' + ''.join(Fstate[i])
    return Fstate

#AES Ciphering Algorithm
def AES_Cipher(Mes,Key):
    '''Mes must be either a string of bytes in hexadecimal form, example 0xabaa10, or of byte type'''
    if type(Mes) == str:
        M = b''
        for i in range(0,len(Mes[2:]),2):
            M += bytes([int(Mes[2:][i]+Mes[2:][i+1],16)])
    else:
        M = Mes
    K = ExpandKey(Key)
    M = Message2State(M)
    cypher = []
    Cypher = '0x'
    for j in M:
        State = AddRoundKey(j,K[:Nb])
        for i in range(1,Nr):
            print('Round[%d] start:' % i , State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
            State = SubWords(State)
            print('Round[%d] s_box:' % i , State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
            State = ShiftRow(State)
            print('Round[%d] s_row:' % i , State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
            State = MixingColumns(State)
            print('Round[%d] m_col:' % i , State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
            State = AddRoundKey(State,K[i*Nb:(i+1)*Nb])
            print('Round[%d] k_sch:' % i, hexa_2(K[i*Nb]) + ''.join(hexa_2(K[i])[2:] for i in [i*Nb + x for x in range(1,Nb)]))
        print('Round[10] start:', State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
        State = SubWords(State)
        print('Round[10] s_box:', State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
        State = ShiftRow(State)
        print('Round[10] s_row:', State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
        State = AddRoundKey(State,K[Nr*Nb:(Nr+1)*Nb])
        print('Round[10] k_sch:', State[0] + ''.join([State[i][2:] for i in [1,2,3]]))
        cypher.append(State)
        for k in State:
            Cypher += k[2:]
    return Cypher
#    return cypher

#AES Deciphering Algorithm
def AES_Deciphering(m,Key):
    if type(m) != list:
        i = 0
        tmp = []
        M = []
        for i in range(len(m[2:])//32):
            M.append([])
            tmp.append(m[2:][i*32:(i+1)*32])
        for j in range(len(tmp)):
            M[j] = ['0x'+tmp[j][8*k:(k+1)*8] for k in range(len(tmp[j])//8)]
    K = ExpandKey(Key)
    message = []
    for x in M:
        State = AddRoundKey(x,K[Nr*Nb:(Nr+1)*Nb])
        for i in range(Nr-1,0,-1):
            State = InvSubWords(State)
            State = InvShiftRow(State)
            State = AddRoundKey(State,K[i*Nb:(i+1)*Nb])
            State = InvMixingColumns(State)
        State = InvSubWords(State)
        State = InvShiftRow(State)
        State = AddRoundKey(State,K[:Nb])
        message.append(State)       
    lenM = int(message[-1][-1],16)//8 * 2 #multiplying by 2 because 0xab has 2 strings but represents 1 byte
    Message = ''
    for i in message:
        for j in i:
            Message += j[2:]
    if Message[lenM:lenM+2] != '80':
        raise ValueError('Message not deciphered correctly')
    Message = Message[:lenM]
    FinalM = b''
    for i in range(lenM//2):
        FinalM += bytes([int(Message[2*i:2*(i+1)],16)])
    print('Message in byte form:\n%s' % FinalM,'\nMessage in hex form:\n%s' % '0x'+Message)

# =============================================================================
#              CREATING THE MESSAGE AND KEY FROM THE BYTES GIVEN
# =============================================================================
message = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
Message = []
for i in message:
    Message.append(bytes([i]))
Message = b''.join(Message)
key = [hexa_2(a)[2:] for a in range(0x0f+1)]
Key = ''.join(key)
Key = ['0x'+ Key[i*8:8*(i+1)] for i in range(4)]



#Round[2] s_row: 0xa7be1a6997ad739bd8c9ca451f618b61
#Round[2] m_col: 0xff87968431d86a51645151fa0773ad09

