#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#define OPCODE_N 5
#define F_LEN 16

//vm_stack:0x
// FLAG:g0odjo0bvm1se4sy

char *vm_stack;
char enc_flag[] = {109, 60, 101, 112, 98, 101, 60, 106, 126, 103, 59, 121, 111, 64, 121, 115};

enum regist{

    R1 = 0xa8,
    R2 = 0xa9,
    R3 = 0xb0,
};

enum opcodes
{
    MOV = 0xd4,
    XOR = 0x90,
    RET = 0x58,
    READ = 0x8c,
    ADD = 0x86,
};



unsigned char vm_code[] = {
	0x8c,
    0xd4,0xa8,0x0,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x30,0x00,
    0xd4,0xa8,0x1,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x31,0x00,
    0xd4,0xa8,0x2,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x32,0x00,
    0xd4,0xa8,0x3,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x33,0x00,
    0xd4,0xa8,0x4,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x34,0x00,
    0xd4,0xa8,0x5,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x35,0x00,
    0xd4,0xa8,0x6,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x36,0x00,
    0xd4,0xa8,0x7,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x37,0x00,
    0xd4,0xa8,0x8,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x38,0x00,
    0xd4,0xa8,0x9,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x39,0x00,
    0xd4,0xa8,0xa,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3a,0x00,
    0xd4,0xa8,0xb,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3b,0x00,
    0xd4,0xa8,0xc,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3c,0x00,
    0xd4,0xa8,0xd,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3d,0x00,
    0xd4,0xa8,0xe,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3e,0x00,
    0xd4,0xa8,0xf,0x00,0x90,0x86,0x21,0x00,0xd4,0xc8,0x3f,0x00,
    0xd4,0xa8,0x10,0x00,0x90,0x86,0x19,0x01,0xd4,0xc8,0x40,0x00,
    0x58
};


typedef struct
{
	unsigned char opcode;
	void (*handle)(void *);

}vm_opcode;

typedef struct vm_cpus
{
    int r1;	
    int r2;	
    int r3;
    unsigned char *eip;	
    vm_opcode op_list[OPCODE_N];

}vm_cpu;


void mov(vm_cpu *cpu); 
void xor(vm_cpu *cpu); 
void read_(vm_cpu *cpu); 
void add_(vm_cpu *cpu);  

void add_(vm_cpu *cpu)
{
    unsigned char *mode = cpu->eip + 1;
    unsigned char *num = cpu->eip + 2;
    int temp;
    switch (*mode){
        case 0x19:
        {
            temp = cpu->r1 + (*num);
            cpu->r1 = temp;
            break;
        }
        case 0x21:
        {
            temp = cpu->r1 + cpu->r3;
            cpu->r1 = temp;
            break;
        }
    }
    cpu->eip +=3;
}

void xor(vm_cpu *cpu)
{  
    int temp;
    temp = cpu->r1 ^ cpu->r2;
    temp ^= 0x3;
    cpu->r1 = temp;
    cpu->eip +=1;           
}

void read_(vm_cpu *cpu)
{

    char *dest = vm_stack;
    read(0,dest,16);      
    cpu->eip += 1; 
}

void mov(vm_cpu *cpu)
{

    unsigned char *res = cpu->eip + 1;  
    //int *offset = (int *) (cpu->eip + 2);    
    unsigned char *offset = cpu->eip + 2;
    char *dest = 0;
    dest = vm_stack;


    switch (*res) {
        case 0xa8:
            cpu->r1 = *(dest + *offset);
            break;    

        case 0xa9:
            cpu->r2 = *(dest + *offset);
            break;    

        case 0xc8:
        {
            int x = cpu->r1;
            *(dest + *offset) = x;
            break;
            
        }
    }    

    cpu->eip += 4;
}    


void vm_init(vm_cpu *cpu)	
{
    cpu->r1 = 0;
    cpu->r2 = 0x8;
    cpu->r3 = 1;

    cpu->eip = (unsigned char *)vm_code;

    cpu->op_list[0].opcode = 0xd4;
    cpu->op_list[0].handle = (void (*)(void *))mov;

    cpu->op_list[1].opcode = 0x90;
    cpu->op_list[1].handle = (void (*)(void *))xor;

    cpu->op_list[2].opcode = 0x8c;
    cpu->op_list[2].handle = (void (*)(void *))read_;

    cpu->op_list[3].opcode = 0x86;
    cpu->op_list[3].handle = (void (*)(void *))add_;

    vm_stack = malloc(0x100);
    memset(vm_stack,0,0x100);
}

void vm_dispatcher(vm_cpu *cpu)
{
    int i;
    for(i=0 ; i < OPCODE_N ; i++)
    {
        if(*cpu->eip == cpu->op_list[i].opcode)	
        {
            cpu->op_list[i].handle(cpu);
            break;
        }
    }
    
}

void vm_start(vm_cpu *cpu)
{

    cpu->eip = (unsigned char*)vm_code;
    while((*cpu->eip)!= RET)
    {
        vm_dispatcher(cpu);
    }

}



void check()
{
    int i;
    char *target = vm_stack;
    for(i = 0; i < F_LEN; i++)
    {
        int offset = i + 0x30;
        if((char)target[offset] != enc_flag[i])
        {
            puts("not correct:( sorry...");
            exit(0);
        }
        else
        {
            continue;
        }
    }
    puts("congratulation!you got me:D");
    exit(0);
}

int main()
{
    vm_cpu *cpu={0};
    puts("feed me your flag!:");
    vm_init(&cpu);
    vm_start(&cpu);
    check();
	return 0;
}
