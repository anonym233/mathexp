#include<stdio.h>
#include<stdlib.h>
#include <conio.h>
#include"miracl.h"
#include<math.h>
#include<time.h>
int main()
{
	miracl *mip=mirsys(5000,10);
	big d[5],k[5],S[3],Sq[3],t[3];
	big K,x,y,N,M,m,l,eq,ans,num;
	int i,j,a[3];
	i=0;j=0;
	K=mirvar(0);
	x=mirvar(0);
	N=mirvar(1);
	M=mirvar(0);
    y=mirvar(1);
	m=mirvar(1);
	l=mirvar(0);
	eq=mirvar(1);
	ans=mirvar(0);
	num=mirvar(0);
	for(i=0;i<5;i++)
		d[i]=mirvar(0);
	for(i=0;i<5;i++)
		k[i]=mirvar(0);
	for(i=0;i<3;i++){
		S[i]=mirvar(0);}
	for(i=0;i<3;i++)
		Sq[i]=mirvar(0);
	for(i=0;i<3;i++)
		t[i]=mirvar(0);
	
	while(1)
	{
		
		bigdig(101,10,d[4]);                       //随机生成d
		i=0;
		do
		{
			bigrand(d[4-i],d[3-i]);
			i++;
		}while(i<4);
		
		i=0;
		while(i<4)                               //互素判断
		{
			j=i+1;
			while(j<5)
			{
				egcd(d[i],d[j],x);
				if(compare(y,x)!=0)
					break;
				j++;
			}
			if(compare(y,x)!=0)
				break;
			i++;
		}
		//（3，4）
		if(compare(y,x)==0)
		{
			multiply(d[0],d[1],N);
			multiply(N,d[2],N);
			multiply(d[3],d[4],M);
			bigdig(300,10,K);
			if((compare(K,M)==1)&&(compare(N,K)==1))
				break;
		}
	}
    printf("随机生成的d为:\n"
		);
	for(i=0;i<5;i++)
		cotnum(d[i],stdout);
	printf("\n");
	printf("N=");
	cotnum(N,stdout);
	printf("\n");
	printf("M=");
	cotnum(M,stdout);
	printf("\n");
	printf("K=");
	cotnum(K,stdout);
	//k0...k4
	for(i=0;i<5;i++)
		powmod(K,y,d[i],k[i]);
	printf("生成的k为:\n");
	for(i=0;i<5;i++)
		cotnum(k[i],stdout);
	//3不等子秘密
	do
	{
		srand((unsigned)time(NULL));
		a[0]=rand()%5;
		a[1]=rand()%5;
		a[2]=rand()%5;
	}while(a[0]==a[1]||a[0]==a[2]||a[1]==a[2]);
	printf("要用到的子秘密分别是:\n");
	printf("%d %d %d\n",a[0],a[1],a[2]);
	//中国剩余定理
	for(i=0;i<3;i++)
		multiply(m,d[a[i]],m);
	copy(m,l);
	for(i=0;i<3;i++)
	{
		divide(m,d[a[i]],S[i]);
		
		copy(l,m);
	}
	for(i=0;i<3;i++)
		xgcd(S[i],d[a[i]],Sq[i],d[a[i]],mirvar(1));
	for(i=0;i<3;i++)
	{
		multiply(S[i],Sq[i],eq);
		multiply(eq,k[a[i]],t[i]);
		powmod(t[i],y,m,t[i]);
	}
	for(i=0;i<3;i++)
		add(num,t[i],num);
	powmod(num,y,m,ans);
	printf("根据中国剩余定理得到结果为:\n");
	cotnum(ans,stdout);
	if(compare(ans,K)==0)
		printf("成功\n");
	else
	    printf("失败\n");

	return 0;
}