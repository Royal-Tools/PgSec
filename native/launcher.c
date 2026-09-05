#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

/* Optional C launcher. Default packaging uses native/pg-sec-audit.sh so the
 * entrypoint has no glibc version requirement. If you compile this file, do it
 * on glibc <= the oldest target (RHEL 8 is 2.28), e.g. manylinux_2_28. */
static int join(char *out,size_t n,const char *a,const char *b){return snprintf(out,n,"%s/%s",a,b)>=(int)n?-1:0;}
int main(int argc,char **argv){
    char exe[PATH_MAX],rootbuf[PATH_MAX],pyhome[PATH_MAX],python[PATH_MAX],script[PATH_MAX],sshhelper[PATH_MAX],libdir[PATH_MAX],rtlib[PATH_MAX];
    ssize_t r=readlink("/proc/self/exe",exe,sizeof(exe)-1); if(r<0){perror("readlink");return 70;} exe[r]=0;
    strncpy(rootbuf,exe,sizeof(rootbuf)-1);rootbuf[sizeof(rootbuf)-1]=0;char *root=dirname(rootbuf);
    if(join(pyhome,sizeof(pyhome),root,"runtime")||join(python,sizeof(python),pyhome,"bin/python3.13")||join(script,sizeof(script),root,"app/pg-sec-audit.py")||join(sshhelper,sizeof(sshhelper),root,"bin/pgssh")||join(libdir,sizeof(libdir),root,"lib")||join(rtlib,sizeof(rtlib),pyhome,"lib")){fprintf(stderr,"pg-sec-audit: path too long\n");return 70;}
    if(access(python,X_OK)!=0){
        if(join(python,sizeof(python),pyhome,"bin/python3")){fprintf(stderr,"pg-sec-audit: path too long\n");return 70;}
    }
    setenv("PYTHONHOME",pyhome,1);setenv("PYTHONNOUSERSITE","1",1);setenv("PYTHONDONTWRITEBYTECODE","1",1);setenv("PGSEC_SSH_HELPER",sshhelper,1);
    const char *old=getenv("LD_LIBRARY_PATH");char ld[PATH_MAX*3];
    snprintf(ld,sizeof(ld),"%s:%s%s%s",rtlib,libdir,old?":":"",old?old:"");setenv("LD_LIBRARY_PATH",ld,1);
    char **na=calloc((size_t)argc+2,sizeof(char*));if(!na){perror("calloc");return 70;}na[0]=python;na[1]=script;for(int i=1;i<argc;i++)na[i+1]=argv[i];na[argc+1]=NULL;
    execv(python,na);fprintf(stderr,"pg-sec-audit: exec failed: %s\n",strerror(errno));return 70;
}
