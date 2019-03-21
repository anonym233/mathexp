#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miracl.h"
#include <math.h>

int main()
{
	big a,m,x,one,r,m1;
	double p;
	int k;
	int flag = 0;
	char ms[128]="";
	char temp[128]="";
	FILE *fp;
	miracl *mip = mirsys(50000, 16);
	one = mirvar(0);
	a = mirvar(0);
	m = mirvar(0);
	x = mirvar(0);
	r = mirvar(0);
	m1 = mirvar(0);

	fp = fopen("test.txt","r");
	fscanf(fp,"%s %d",ms,&k);
	printf("m = %s k = %d\n",ms,k);
    cinstr(m,ms);
	if(!(int)(ms[strlen(ms)-1])%2){
		printf("不是奇整数。");
		return 0;
	}
	convert(1,one);
	incr(m,-1, m1);//将一个大数减一个整数
	do 
	{	
		while (1)
		{
			bigrand(m1, a);//使用内置随机数发生器，产生一个小于M1的大数随机数
			if (compare(a,one))
				break;
		}
		egcd(a,m,x);
		cotstr(x,temp);
		printf("x = %s",temp);
		cotstr(a,temp);
		printf(" a = %s\n",temp);
		if(compare(x,one) == 0)
		{
			powmod(a,m1,m,r);
			if(compare(r,one)==0)
			{
				flag++;
				p = 1-(1/pow(2,flag));
			}else{
				printf("m为合数 %d",flag);
				return 0;
				}
		}
	} while (flag<k);
	printf("m可能是素数，可能性是%.2f\n",p*100);
	system("pause");
	return 0;
}
