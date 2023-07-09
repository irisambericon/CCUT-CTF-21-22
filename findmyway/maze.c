#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>


unsigned char maze[26]={'O','I','I','I','I',
						'O','O','I','O','#',
						'I','O','O','O','I',
						'I','O','I','O','I',
						'I','I','I','I','I',
};

int row1=0;
int col1=0;
int *rowp=&row1;
int *colp=&col1;

void movedown(int *row,int *col){
	int row_now=0;
	row_now=(*row)+1;
	*row=row_now;
	if(maze[5*row_now+(*col)]=='I' || row_now>4){
		puts("ouch,hit the wall...\n");
		system("pause");
		exit(0);
	}
}

void moveup(int *row,int *col){
	int row_now=0;
	row_now=(*row)-1;
	*row=row_now;
	if(maze[5*row_now+(*col)]=='I' || row_now<0){
		puts("ouch,hit the wall...\n");
		system("pause");
		exit(0);
	}
}

void moveright(int *row,int *col){
	int col_now=0;
	col_now=(*col)+1;
	*col=col_now;
	int tmp=maze[5*(*row)+col_now];
	if(tmp =='I' || col_now>4){
		puts("ouch,hit the wall...\n");
		system("pause");
		exit(0);
	}
	
	if(tmp=='#'){
		puts("good j0bb!!");
		puts("flag is the value of md5{your_path}");
		system("pause");
		exit(0);
	}
}

void moveleft(int *row,int *col){
	int col_now=0;
	col_now=(*col)-1;
	*col=col_now;
	int tmp=maze[5*(*row)+col_now];
	
	if(tmp =='I' || col_now<0){
		puts("ouch,hit the wall...\n");
		system("pause");
		exit(0);
	}
}

VOID magic(VOID){
	BOOL mgc=IsDebuggerPresent();
	if(mgc){
		exit(0);
	}
}


int main(){
	magic();
	
	unsigned char input_path[16]="";
	unsigned char tmp=0;
	int len_in_path=0;
	int i=0;
	
	puts("find your way out!\n");
	scanf("%12s",input_path);
	len_in_path=strlen(input_path);
	if(!len_in_path || len_in_path>12){
		puts("your input is malformed...\n");
		system("pause");
		exit(0);
	}
	
	for(i=0;i<len_in_path;i++){
		
		tmp=input_path[i];
		
		if(tmp=='w'){
			moveup(rowp,colp);
		}
		if(tmp=='a'){
			moveleft(rowp,colp);
		}
		if(tmp=='s'){
			movedown(rowp,colp);
		}
		if(tmp=='d'){
			moveright(rowp,colp);
		}
	}
	system("pause");
	exit(0);
}
