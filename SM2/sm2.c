#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <memory.h>
#include <time.h>
#include "sm2.h"

#define SM2_PAD_ZERO TRUE
#define SM2_DEBUG   0
struct FPECC{
char *p;
char *a;
char *b;
char *n;
char *x;
char *y;
};
/*SM2 Fp256*/
struct FPECC Ecc256 = {
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};
unsigned char radom1[] = { 0x4C,0x62,0xEE,0xFD,0x6E,0xCF,0xC2,0xB9,0x5B,0x92,0xFD,0x6C,0x3D,0x95,0x75,0x14,0x8A,0xFA,0x17,0x42,0x55,0x46,0xD4,0x90,0x18,0xE5,0x38,0x8D,0x49,0xDD,0x7B,0x4F };

void PrintBuf(unsigned char *buf, int	buflen)
{
	int i;
	for (i = 0; i < buflen; i++) {		
			printf("%02x", buf[i]);
	}
	printf("\n");
	return 0;
}
void Printch(unsigned char *buf, int	buflen)
{
	int i;
	for (i = 0; i < buflen; i++) {
		if (i % 32 != 31)
			printf("%c", buf[i]);
		
	}
	printf("\n");
	return 0;
}

//获取公私钥
void sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, int *wylen,unsigned char *privkey, int *privkeylen)
{

	struct FPECC *cfig = &Ecc256;
	epoint *g;
    big a,b,p,n,x,y,key1;
    miracl *mip = mirsys(20,0);
    mip->IOBASE = 16;
    p = mirvar(0);
	a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    key1 = mirvar(0);
    cinstr(p,cfig->p);//转换为大数
	cinstr(a,cfig->a);
    cinstr(b,cfig->b);
	cinstr(n,cfig->n);
	cinstr(x,cfig->x);
    cinstr(y,cfig->y);
	ecurve_init(a,b,p,MR_PROJECTIVE);
    g = epoint_init();          //初始化点
    epoint_set(x,y,0,g);     //设置点坐标
    irand(time(NULL));
    bigrand(n,key1);   ////私钥db
    ecurve_mult(key1,g,g); //计算Pb
    epoint_get(g,x,y);
    *wxlen = big_to_bytes(32, x, (char *)wx, TRUE);
   	*wylen = big_to_bytes(32, y, (char *)wy, TRUE);
	*privkeylen = big_to_bytes(32, key1, (char *)privkey, TRUE);
	mirkill(key1);
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	epoint_free(g);
	mirexit();
}

//密钥派生
int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf)
{
	/*
	return 0: kbuf = 0, 不可
		   1: kbuf 可
	*/
	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001; //初始化一个32比特构成的计数器ct=0x00000001
	int i, m, n;
	unsigned char *p;
	memcpy(buf, zl, 32);
	memcpy(buf+32, zr, 32);
	m = klen / 32;
	n = klen % 32;
	p = kbuf;
	for(i = 0; i < m; i++)
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, p);
		p += 32;
		ct++;
	}
	/*对i从1到?klen/v?执行：b.1)计算Hai=Hv(Z ∥ ct)；b.2) ct++*/
	if(n != 0)
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, digest);
	}
	/*若klen/v是整数，令Ha!?klen/v? = Ha?klen/v?，否则令Ha!?klen/v?为Ha?klen/v?最左边的(klen ?
(v × ?klen/v?))比特*/
	memcpy(p, digest, n);
	/*令K = Ha1||Ha2||  ||*/
	for(i = 0; i < klen; i++)
	{
		if(kbuf[i] != 0)
			break;
	}

	if(i < klen)
		return 1;
	else
		return 0;

}

//加密函数
int sm2_encrypt(unsigned char *msg,int msglen, unsigned char *wx,int wxlen, unsigned char *wy,int wylen, unsigned char *outmsg)
{

	struct FPECC *cfig = &Ecc256;
    big x2, y2, c1, c2, k;
    big a,b,p,n,x,y;
    epoint *g, *w;
	int ret = -1;
	int i;
	unsigned char zl[32], zr[32];
	unsigned char *tmp;
    miracl *mip;
	tmp = malloc(msglen+64);
	if(tmp == NULL)
		return -1;
	mip = mirsys(20, 0);
	mip->IOBASE = 16;
    p=mirvar(0);
	a=mirvar(0);
    b=mirvar(0);
    n=mirvar(0);
    x=mirvar(0);
    y=mirvar(0);
	k=mirvar(0);
	x2=mirvar(0); 
	y2=mirvar(0); 
	c1=mirvar(0); 
	c2=mirvar(0); 
    cinstr(p,cfig->p);
	cinstr(a,cfig->a);
    cinstr(b,cfig->b);
	cinstr(n,cfig->n);
	cinstr(x,cfig->x);
    cinstr(y,cfig->y);
	ecurve_init(a,b,p,MR_PROJECTIVE);
    g=epoint_init();
	w=epoint_init();
    epoint_set(x,y,0,g);
	bytes_to_big(wxlen,(char *)wx,x);
	bytes_to_big(wylen,(char *)wy,y);
	epoint_set(x,y,0,w);
    irand(time(NULL));
sm2_encrypt_again:
#if SM2_DEBUG
	bytes_to_big(32, (char *)radom1, k);
#else
	do
	{
		bigrand(n, k);
	} 
	while (k->len == 0);
#endif
	ecurve_mult(k, g, g);
	epoint_get(g, c1, c2);
	big_to_bytes(32, c1, (char *)outmsg, TRUE);
	big_to_bytes(32, c2, (char *)outmsg+32, TRUE);
	//计算椭圆曲线点C1
	if(point_at_infinity(w))
		goto exit_sm2_encrypt;
	//计算椭圆曲线点S
	ecurve_mult(k, w, w);
	epoint_get(w, x2, y2);
	big_to_bytes(32, x2, (char *)zl, TRUE);
	big_to_bytes(32, y2, (char *)zr, TRUE);
	//计算椭圆曲线点[k]PB
	if (kdf(zl, zr, msglen, outmsg+64) == 0)
		goto sm2_encrypt_again;
	//计算t = KDF,如果t全零,返回A1
	for(i = 0; i < msglen; i++)
	{
		outmsg[64+i] ^= msg[i];
	}
	//计算C2
	memcpy(tmp, zl, 32);
	memcpy(tmp+32, msg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	sm3(tmp, 64+msglen, &outmsg[64+msglen]);
	//计算C3
	ret = msglen+64+32;
	printf("key:");
	cotnum(k, stdout);
	//输出C,C在outmsg
exit_sm2_encrypt:
	mirkill(x2);  
	mirkill(y2);  
	mirkill(c1);  
	mirkill(c2);  
	mirkill(k);
	mirkill(a);  
	mirkill(b);
    mirkill(p);  
	mirkill(n);  
	mirkill(x);
	mirkill(y);
    epoint_free(g); 
	epoint_free(w);
	mirexit();
	free(tmp);
	return ret;
}

//解密函数
int sm2_decrypt(unsigned char *msg,int msglen, unsigned char *privkey, int privkeylen, unsigned char *outmsg)
{

	struct FPECC *cfig = &Ecc256;
    big x2, y2, c, k;
    big a,b,p,n,x,y,key1;
    epoint *g;
	unsigned char c3[32];
	unsigned char zl[32], zr[32];
	int i, ret = -1;
	unsigned char *tmp;
    miracl *mip;
	if(msglen < 96)
		return 0;
	msglen -= 96;
	tmp = malloc(msglen+64);
	if(tmp == NULL)
		return 0;
	mip = mirsys(20, 0);
	mip->IOBASE = 16;
	x2=mirvar(0); 
	y2=mirvar(0); 
	c=mirvar(0); 
	k = mirvar(0);
    p = mirvar(0);
	a = mirvar(0);
    b = mirvar(0);
    n = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    key1 = mirvar(0);
    bytes_to_big(privkeylen,(char *)privkey,key1);
    cinstr(p,cfig->p);
	cinstr(a,cfig->a);
    cinstr(b,cfig->b);
	cinstr(n,cfig->n);
	cinstr(x,cfig->x);
    cinstr(y,cfig->y);
	ecurve_init(a,b,p,MR_PROJECTIVE);
    g = epoint_init();
	bytes_to_big(32, (char *)msg, x);
	bytes_to_big(32, (char *)msg+32, y);
    if(!epoint_set(x,y,0,g))
		goto exit_sm2_decrypt;  //检验是否为椭圆曲线
	if(point_at_infinity(g))
		goto exit_sm2_decrypt;  //计算S
	ecurve_mult(key1, g, g);
	epoint_get(g, x2, y2);	
	big_to_bytes(32, x2, (char *)zl, TRUE);
	big_to_bytes(32, y2, (char *)zr, TRUE); //计算[db]c1
	if (kdf(zl, zr, msglen, outmsg) == 0)
		goto exit_sm2_decrypt;    //计算t
	for(i = 0; i < msglen; i++)
	{
		outmsg[i] ^= msg[i+64];
	}   //计算M到outsmg
	memcpy(tmp, zl, 32);
	memcpy(tmp+32, outmsg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	sm3(tmp, 64+msglen, c3);//计算u
	if(memcmp(c3, msg+64+msglen, 32) != 0)
		goto exit_sm2_decrypt;
	ret =  msglen;
exit_sm2_decrypt:
	mirkill(x2);  
	mirkill(y2);  
	mirkill(c);  
	mirkill(k);
	mirkill(p);
	mirkill(a); 
	mirkill(b); 
	mirkill(n); 
	mirkill(x); 
	mirkill(y); 
	mirkill(key1);
    epoint_free(g);
	mirexit();
	free(tmp);
	return ret;
}
int main()
{
	unsigned char dB[] = { 0x16,0x49,0xAB,0x77,0xA0,0x06,0x37,0xBD,0x5E,0x2E,0xFE,0x28,0x3F,0xBF,0x35,0x35,0x34,0xAA,0x7F,0x7C,0xB8,0x94,0x63,0xF2,0x08,0xDD,0xBC,0x29,0x20,0xBB,0x0D,0xA0 };
	unsigned char xB[] = { 0x43,0x5B,0x39,0xCC,0xA8,0xF3,0xB5,0x08,0xC1,0x48,0x8A,0xFC,0x67,0xBE,0x49,0x1A,0x0F,0x7B,0xA0,0x7E,0x58,0x1A,0x0E,0x48,0x49,0xA5,0xCF,0x70,0x62,0x8A,0x7E,0x0A };
	unsigned char yB[] = { 0x75,0xDD,0xBA,0x78,0xF1,0x5F,0xEE,0xCB,0x4C,0x78,0x95,0xE2,0xC1,0xCD,0xF5,0xFE,0x01,0xDE,0xBB,0x2C,0xDB,0xAD,0xF4,0x53,0x99,0xCC,0xF7,0x7B,0xBA,0x07,0x6A,0x42 };
	unsigned char tx[256];
	unsigned char etx[256];
	unsigned char mtx[256];
	FILE *fp=0;
	int wxlen, wylen, privkeylen,len;
	fp=fopen("5.txt", "r");
	len=fread(tx, sizeof(unsigned char), 256, fp);
	tx[len] = "\0";
	sm2_keygen(xB, &wxlen, yB, &wylen, dB, &privkeylen);
	printf("dB: ");
	PrintBuf(dB, 32);
	printf("xB: ");
	PrintBuf(xB, 32);
	printf("yB: ");
	PrintBuf(yB, 32);
	sm2_encrypt(tx,len,xB,32,yB,32,etx);
	printf("\n``````````````````this is encrypt```````````````````\n");
	PrintBuf(etx, 64 +len + 32);
	printf("\n``````````````````this is decrypt```````````````````\n");
	sm2_decrypt(etx,64+len+32,dB,32,mtx);
	if(sm2_decrypt(etx,64+len+32,dB,32,mtx) < 0)

		printf("sm2_decrypt error!\n");
	else
	{
		PrintBuf(mtx, len);
		Printch(mtx, len);
	}

	return 0;
}
