flag="g0odjo0bvm1se4sy"
enc=""
enc_num=[]
for i in range(len(flag)):
    enc+=chr(((ord(flag[i])^0x8)^0x3)+1)
    enc_num.append(ord(enc[i]))
print(enc)
print(enc_num)

enced="m<epbe<j~g;yo@ys"
dec=""
for i in range(len(enced)):
    dec+=chr(((ord(enced[i])-1)^0x3)^0x8)
print(dec)