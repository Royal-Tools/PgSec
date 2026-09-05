#define _POSIX_C_SOURCE 200809L
#include <libssh2.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(FILE *f) {
    fprintf(f,
      "pgssh - minimal SSH execution helper for pg-sec-audit\n"
      "Usage: pgssh --host HOST --port PORT --user USER --known-hosts FILE --command-b64 B64\n"
      "             [--key PRIVATE_KEY | --password-stdin] [--accept-new]\n");
}
static const char *argval(int argc, char **argv, const char *key) {
    for (int i=1;i+1<argc;i++) if (!strcmp(argv[i],key)) return argv[i+1];
    return NULL;
}
static int hasarg(int argc,char **argv,const char *key){for(int i=1;i<argc;i++)if(!strcmp(argv[i],key))return 1;return 0;}
static void die_session(LIBSSH2_SESSION *s, const char *msg, int rc) {
    char *err=NULL; int len=0; if(s) libssh2_session_last_error(s,&err,&len,0);
    if(err && len) fprintf(stderr,"pgssh: %s (rc=%d): %.*s\n",msg,rc,len,err);
    else fprintf(stderr,"pgssh: %s (rc=%d)\n",msg,rc);
}
static char *read_password(void) {
    char buf[4096]; if(!fgets(buf,sizeof(buf),stdin)) return strdup("");
    size_t n=strlen(buf); while(n && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n]=0;
    return strdup(buf);
}
static int b64v(char c){if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='+')return 62;if(c=='/')return 63;return -1;}
static unsigned char *b64decode(const char *in,size_t *outlen){
    size_t n=strlen(in), cap=(n/4+1)*3; unsigned char *out=malloc(cap+1); if(!out)return NULL;
    size_t j=0; int val=0,bits=-8;
    for(size_t i=0;i<n;i++){if(in[i]=='=')break;int x=b64v(in[i]);if(x<0)continue;val=(val<<6)|x;bits+=6;if(bits>=0){out[j++]=(unsigned char)((val>>bits)&0xff);bits-=8;}}
    out[j]=0;*outlen=j;return out;
}
static int mkdir_parents(const char *path){
    char *p=strdup(path);if(!p)return -1;char *slash=strrchr(p,'/');if(!slash){free(p);return 0;}*slash=0;
    if(!*p){free(p);return 0;} for(char *q=p+1;*q;q++){if(*q=='/'){*q=0;mkdir(p,0700);*q='/';}} mkdir(p,0700);free(p);return 0;
}
static int keymask(int t){
    switch(t){
      case LIBSSH2_HOSTKEY_TYPE_RSA:return LIBSSH2_KNOWNHOST_KEY_SSHRSA;
      case LIBSSH2_HOSTKEY_TYPE_DSS:return LIBSSH2_KNOWNHOST_KEY_SSHDSS;
      case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:return LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
      case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:return LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
      case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:return LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
      case LIBSSH2_HOSTKEY_TYPE_ED25519:return LIBSSH2_KNOWNHOST_KEY_ED25519;
      default:return LIBSSH2_KNOWNHOST_KEY_UNKNOWN;
    }
}
static int connect_tcp(const char *host,const char *port){
    struct addrinfo hints,*res=NULL,*rp; memset(&hints,0,sizeof(hints));hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
    int rc=getaddrinfo(host,port,&hints,&res);if(rc){fprintf(stderr,"pgssh: DNS: %s\n",gai_strerror(rc));return -1;}
    int fd=-1;for(rp=res;rp;rp=rp->ai_next){fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);if(fd<0)continue;if(connect(fd,rp->ai_addr,rp->ai_addrlen)==0)break;close(fd);fd=-1;}freeaddrinfo(res);return fd;
}
int main(int argc,char **argv){
    if(hasarg(argc,argv,"--help")||argc==1){usage(stdout);return 0;}
    const char *host=argval(argc,argv,"--host"),*port_s=argval(argc,argv,"--port"),*user=argval(argc,argv,"--user"),
      *khfile=argval(argc,argv,"--known-hosts"),*cmd64=argval(argc,argv,"--command-b64"),*key=argval(argc,argv,"--key");
    int pass_stdin=hasarg(argc,argv,"--password-stdin"),accept_new=hasarg(argc,argv,"--accept-new");
    if(!host||!port_s||!user||!khfile||!cmd64||(!key&&!pass_stdin)){usage(stderr);return 64;}
    char *end=NULL;long port=strtol(port_s,&end,10);if(!end||*end||port<1||port>65535){fprintf(stderr,"pgssh: invalid port\n");return 64;}
    size_t cmdlen=0;unsigned char *cmd=b64decode(cmd64,&cmdlen);if(!cmd||!cmdlen){fprintf(stderr,"pgssh: invalid command\n");free(cmd);return 64;}
    char *password=pass_stdin?read_password():NULL;
    if(libssh2_init(0)!=0){fprintf(stderr,"pgssh: libssh2 init failed\n");free(cmd);free(password);return 70;}
    char portbuf[16];snprintf(portbuf,sizeof(portbuf),"%ld",port);int sock=connect_tcp(host,portbuf);if(sock<0){fprintf(stderr,"pgssh: cannot connect to %s:%ld\n",host,port);libssh2_exit();free(cmd);free(password);return 69;}
    LIBSSH2_SESSION *s=libssh2_session_init();if(!s){close(sock);libssh2_exit();free(cmd);free(password);return 70;}
    libssh2_session_set_blocking(s,1);
    int rc=libssh2_session_handshake(s,sock);if(rc){die_session(s,"SSH handshake failed",rc);goto fail69;}
    size_t hklen=0;int hktype=0;const char *hk=libssh2_session_hostkey(s,&hklen,&hktype);if(!hk||!hklen){fprintf(stderr,"pgssh: server host key unavailable\n");goto fail69;}
    LIBSSH2_KNOWNHOSTS *hosts=libssh2_knownhost_init(s);if(!hosts){fprintf(stderr,"pgssh: known-hosts init failed\n");goto fail69;}
    (void)libssh2_knownhost_readfile(hosts,khfile,LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    int mask=LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW|keymask(hktype);struct libssh2_knownhost *known=NULL;
    int ck=libssh2_knownhost_checkp(hosts,host,(int)port,hk,hklen,mask,&known);
    if(ck==LIBSSH2_KNOWNHOST_CHECK_MISMATCH){fprintf(stderr,"pgssh: HOST KEY MISMATCH for %s:%ld\n",host,port);libssh2_knownhost_free(hosts);goto fail68;}
    if(ck!=LIBSSH2_KNOWNHOST_CHECK_MATCH){
      if(!accept_new){fprintf(stderr,"pgssh: unknown host key for %s:%ld (use --accept-new to trust first use)\n",host,port);libssh2_knownhost_free(hosts);goto fail68;}
      mkdir_parents(khfile);char hname[1024];if(port==22)snprintf(hname,sizeof(hname),"%s",host);else snprintf(hname,sizeof(hname),"[%s]:%ld",host,port);
      if(libssh2_knownhost_addc(hosts,hname,NULL,hk,hklen,"pg-sec-audit",12,mask,&known)!=0 || libssh2_knownhost_writefile(hosts,khfile,LIBSSH2_KNOWNHOST_FILE_OPENSSH)<0){fprintf(stderr,"pgssh: failed to persist known host key\n");libssh2_knownhost_free(hosts);goto fail68;}
      chmod(khfile,0600);
    }
    libssh2_knownhost_free(hosts);
    if(key) rc=libssh2_userauth_publickey_fromfile(s,user,NULL,key,NULL); else rc=libssh2_userauth_password(s,user,password?password:"");
    if(password){memset(password,0,strlen(password));free(password);password=NULL;}
    if(rc){die_session(s,"authentication failed",rc);goto fail67;}
    LIBSSH2_CHANNEL *ch=libssh2_channel_open_session(s);if(!ch){die_session(s,"open channel failed",-1);goto fail69;}
    rc=libssh2_channel_exec(ch,(const char*)cmd);memset(cmd,0,cmdlen);free(cmd);cmd=NULL;if(rc){die_session(s,"exec failed",rc);libssh2_channel_free(ch);goto fail69;}
    char buf[16384];ssize_t n;
    while((n=libssh2_channel_read(ch,buf,sizeof(buf)))>0) fwrite(buf,1,(size_t)n,stdout);
    while((n=libssh2_channel_read_stderr(ch,buf,sizeof(buf)))>0) fwrite(buf,1,(size_t)n,stderr);
    libssh2_channel_send_eof(ch);libssh2_channel_wait_eof(ch);libssh2_channel_wait_closed(ch);int status=libssh2_channel_get_exit_status(ch);libssh2_channel_free(ch);
    libssh2_session_disconnect(s,"pg-sec-audit done");libssh2_session_free(s);close(sock);libssh2_exit();return status;
fail67: if(cmd){memset(cmd,0,cmdlen);free(cmd);} if(password){memset(password,0,strlen(password));free(password);} libssh2_session_disconnect(s,"auth failed");libssh2_session_free(s);close(sock);libssh2_exit();return 67;
fail68: if(cmd){memset(cmd,0,cmdlen);free(cmd);} if(password){memset(password,0,strlen(password));free(password);} libssh2_session_disconnect(s,"host key failure");libssh2_session_free(s);close(sock);libssh2_exit();return 68;
fail69: if(cmd){memset(cmd,0,cmdlen);free(cmd);} if(password){memset(password,0,strlen(password));free(password);} libssh2_session_free(s);close(sock);libssh2_exit();return 69;
}
