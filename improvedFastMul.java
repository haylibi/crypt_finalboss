public byte fastMul(int a, int e){
        while (e != 0x01){
            int sign = (a >> 7) & 0x01;
            a = (a << 1) & 0xFF;
            if (sign == 1)
                a = a ^ 0x1b;
            e = e/2;
        }
        return (byte)a;
    }
    
    public byte xTimes(int a, int e){
        int temp = 0x00;
        for (int i = 7; i >0; i--){
            if (((e >> i) & 0x01) == 1){
                temp = temp ^ fastMul(a, (int)Math.pow(2, i));
            }
        }
        if (e % 2 == 1)
            temp = temp ^ a;
        return (byte)temp;
    }