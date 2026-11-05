/* SPDX-License-Identifier: MIT
 * ROOT-only canary for the experimental frontend. Default: preflight only.
 * Never discovers/opens official NVIDIA devices or submits GPU work. Even an
 * executed successful result does not validate CUDA, GPU kernels or UVM.
 */
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"

#ifndef HYBRID_EXPECTED_KERNEL_RELEASE
#error Build must pin the expected kernel release
#endif
_Static_assert(sizeof(NVOS21_PARAMETERS)==32 && offsetof(NVOS21_PARAMETERS,status)==28, "NVOS21 layout");
_Static_assert(sizeof(NVOS64_PARAMETERS)==48 && offsetof(NVOS64_PARAMETERS,status)==40, "NVOS64 layout");
_Static_assert(sizeof(NVOS00_PARAMETERS)==16 && offsetof(NVOS00_PARAMETERS,status)==12, "NVOS00 layout");
_Static_assert(NV01_ROOT==0 && NV01_ROOT_CLIENT==0x41, "root classes");
_Static_assert(NV_IOCTL_MAGIC=='F' && NV_ESC_RM_ALLOC==0x2b && NV_ESC_RM_FREE==0x29, "ioctl commands");
#define STATUS_UNWRITTEN ((NvV32)0xffffffffU)
#define CANARY_SKIP 77

struct options {
    const char *legacy_pci, *open_pci, *output, *kernel;
    bool execute;
};
struct operation {
    const char *name;
    bool attempted, success;
    int syscall_return, error;
    NvU32 status, klass, root, parent, object;
};
struct result {
    bool kernel_matches, legacy_parameter, open_parameter, legacy_driver, open_driver;
    bool legacy_module, open_module, enabled, misc_identity, preflight, opened, closed;
    bool executed, success;
    int close_error;
    char error[256];
    struct operation operations[4];
};

static void fail(struct result *r, const char *message)
{
    if (r->error[0] == '\0')
        snprintf(r->error, sizeof(r->error), "%s", message);
}

static bool exact_bdf(const char *s)
{
    unsigned int slot;
    if (s == NULL || strlen(s) != 12 || s[4] != ':' || s[7] != ':' || s[10] != '.')
        return false;
    for (size_t i=0; i<12; ++i) {
        if (i==4 || i==7 || i==10) continue;
        if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f')))
            return false;
    }
    slot=(unsigned int)(s[8]<='9' ? s[8]-'0' : s[8]-'a'+10)*16U+
         (unsigned int)(s[9]<='9' ? s[9]-'0' : s[9]-'a'+10);
    return slot<=0x1f && s[11]>='0' && s[11]<='7';
}

static int parse(int argc, char **argv, struct options *o)
{
    bool dry_run=false, execution_flag=false, kernel_seen=false;
    o->kernel=HYBRID_EXPECTED_KERNEL_RELEASE;
    for (int i=1; i<argc; ++i) {
        const char **target=NULL;
        if (!strcmp(argv[i], "--help")) return 1;
        if (!strcmp(argv[i], "--execute")) {
            if (execution_flag || dry_run) return -1;
            execution_flag=o->execute=true;
            continue;
        }
        if (!strcmp(argv[i], "--dry-run")) {
            if (dry_run || execution_flag) return -1;
            dry_run=true;
            continue;
        }
        if (!strcmp(argv[i], "--legacy-pci")) target=&o->legacy_pci;
        else if (!strcmp(argv[i], "--open-pci")) target=&o->open_pci;
        else if (!strcmp(argv[i], "--output")) target=&o->output;
        else if (!strcmp(argv[i], "--kernel-release")) {
            if (kernel_seen) return -1;
            kernel_seen=true;
            if (++i==argc || !argv[i][0] || strlen(argv[i])>127) return -1;
            o->kernel=argv[i];
            continue;
        } else return -1;
        if (*target != NULL || ++i==argc || !argv[i][0]) return -1;
        *target=argv[i];
    }
    return exact_bdf(o->legacy_pci) && exact_bdf(o->open_pci) &&
        strcmp(o->legacy_pci,o->open_pci) && o->output != NULL ? 0 : -1;
}

static int read_text(const char *path, char *buffer, size_t capacity)
{
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    size_t used=0;
    bool complete=false;
    if (fd<0) return -1;
    while (used+1<capacity) {
        ssize_t amount=read(fd,buffer+used,capacity-1-used);
        if (amount<0 && errno==EINTR) continue;
        if (amount<0) break;
        if (amount==0) { complete=true; break; }
        used+=(size_t)amount;
    }
    int rc=close(fd);
    if (!complete || rc!=0) return -1;
    buffer[used]='\0';
    if (used && buffer[used-1]=='\n') buffer[--used]='\0';
    /* Reject embedded NUL/newline instead of accepting a matching prefix. */
    if (strlen(buffer)!=used || strchr(buffer,'\n')!=NULL) return -1;
    return 0;
}

static bool parameter_matches(const char *module, const char *expected)
{
    char path[PATH_MAX], value[128];
    snprintf(path,sizeof(path),"/sys/module/%s/parameters/hybrid_gpu_pci",module);
    return read_text(path,value,sizeof(value))==0 && !strcmp(value,expected);
}

static bool link_matches(const char *path, const char *expected)
{
    char target[PATH_MAX];
    ssize_t length=readlink(path,target,sizeof(target)-1);
    if (length<=0 || (size_t)length>=sizeof(target)-1) return false;
    target[length]='\0';
    const char *last=strrchr(target,'/');
    return !strcmp(last ? last+1 : target, expected);
}

static bool binding_matches(const char *pci, const char *module, bool check_module)
{
    char path[PATH_MAX];
    snprintf(path,sizeof(path),"/sys/bus/pci/devices/%s/driver%s",pci,check_module ? "/module" : "");
    return link_matches(path,module);
}

static bool preflight(const struct options *o, struct result *r, dev_t *device)
{
    struct utsname host;
    char value[128], extra;
    unsigned int dev_major, dev_minor;
    r->kernel_matches=uname(&host)==0 && !strcmp(host.release,o->kernel);
    if (!r->kernel_matches) { fail(r,"kernel release does not match the explicit build expectation"); return false; }
    r->legacy_parameter=parameter_matches("hybrid580_legacy",o->legacy_pci);
    r->open_parameter=parameter_matches("hybrid580_open",o->open_pci);
    if (!r->legacy_parameter || !r->open_parameter) { fail(r,"private backend PCI parameters are absent or differ from the selected BDFs"); return false; }
    r->legacy_driver=binding_matches(o->legacy_pci,"hybrid580_legacy",false);
    r->open_driver=binding_matches(o->open_pci,"hybrid580_open",false);
    r->legacy_module=binding_matches(o->legacy_pci,"hybrid580_legacy",true);
    r->open_module=binding_matches(o->open_pci,"hybrid580_open",true);
    if (!r->legacy_driver || !r->open_driver || !r->legacy_module || !r->open_module) { fail(r,"selected PCI devices are not bound to the expected private drivers and modules"); return false; }
    r->enabled=read_text("/sys/module/hybrid580_frontend/parameters/enable_control",value,sizeof(value))==0 && !strcmp(value,"Y");
    if (!r->enabled) { fail(r,"experimental frontend control interface is not explicitly enabled"); return false; }
    r->misc_identity=read_text("/sys/class/misc/hybrid580ctl/dev",value,sizeof(value))==0 &&
        sscanf(value,"%u:%u%c",&dev_major,&dev_minor,&extra)==2 && dev_major==10 && dev_minor<=255;
    if (!r->misc_identity) { fail(r,"experimental misc device identity is unavailable or invalid"); return false; }
    *device=makedev(dev_major,dev_minor);
    r->preflight=true;
    return true;
}

static bool allocate(int fd, bool wide, struct operation *op)
{
    NVOS21_PARAMETERS p21={0};
    NVOS64_PARAMETERS p64={0};
    int rc, saved;
    p21.hClass=p64.hClass=NV01_ROOT;
    p21.status=p64.status=STATUS_UNWRITTEN;
    op->attempted=true;
    /* Ambiguous failures are never retried. The frontend owns every recorded
     * allocation until known free or final file close, including copy faults. */
    if (wide)
        rc=ioctl(fd,_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&p64);
    else
        rc=ioctl(fd,_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),&p21);
    saved=errno;
    op->syscall_return=rc; op->error=rc<0 ? saved : 0;
    op->status=wide ? p64.status : p21.status;
    op->klass=wide ? p64.hClass : p21.hClass;
    op->root=wide ? p64.hRoot : p21.hRoot;
    op->parent=wide ? p64.hObjectParent : p21.hObjectParent;
    op->object=wide ? p64.hObjectNew : p21.hObjectNew;
    op->success=rc==0 && op->status==NV_OK && op->klass==NV01_ROOT_CLIENT &&
        op->root==0 && op->parent==0 && op->object!=0 &&
        (wide ? (p64.pAllocParms==0 && p64.paramsSize==0 && p64.pRightsRequested==0 && p64.flags==NVOS64_FLAGS_NONE) :
                (p21.pAllocParms==0 && p21.paramsSize==0));
    return op->success;
}

static bool free_root(int fd, NvHandle root, bool parent_is_root, struct operation *op)
{
    NVOS00_PARAMETERS packet={0};
    packet.hRoot=packet.hObjectOld=root;
    packet.hObjectParent=parent_is_root ? root : 0;
    packet.status=STATUS_UNWRITTEN;
    op->attempted=true;
    int rc=ioctl(fd,_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_FREE,NVOS00_PARAMETERS),&packet);
    int saved=errno;
    op->syscall_return=rc; op->error=rc<0 ? saved : 0;
    op->status=packet.status; op->root=packet.hRoot;
    op->parent=packet.hObjectParent; op->object=packet.hObjectOld;
    op->success=rc==0 && packet.status==NV_OK && packet.hRoot==root &&
        packet.hObjectOld==root && packet.hObjectParent==(parent_is_root ? root : 0);
    return op->success;
}

static void execute(const struct options *o, struct result *r, dev_t expected)
{
    struct stat st;
    int fd;
    (void)o;
    r->executed=true;
    /* Refuse a stale/mistyped node before open can invoke another driver's
     * .open. This and the post-open check are observations, not fencing
     * against concurrent privileged replacement/rebinding. */
    if (lstat("/dev/hybrid580ctl",&st)!=0 || !S_ISCHR(st.st_mode) || st.st_rdev!=expected) {
        fail(r,"control path is not the preflight misc character device");
        return;
    }
    fd=open("/dev/hybrid580ctl",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) { fail(r,"opening the experimental control device failed"); return; }
    r->opened=true;
    if (fstat(fd,&st)!=0 || !S_ISCHR(st.st_mode) || st.st_rdev!=expected) {
        fail(r,"opened control file is not the preflight misc character device");
        goto done;
    }
    if (!allocate(fd,false,&r->operations[0])) { fail(r,"NVOS21 ROOT allocation failed or returned an invalid result"); goto done; }
    if (!allocate(fd,true,&r->operations[1])) { fail(r,"NVOS64 ROOT allocation failed or returned an invalid result"); goto done; }
    if (r->operations[0].object==r->operations[1].object) { fail(r,"distinct ROOT allocations returned the same client ID"); goto done; }
    /* Reverse allocation order; exercise both observed parent conventions. */
    if (!free_root(fd,r->operations[1].object,true,&r->operations[2])) { fail(r,"first ROOT free failed or returned an invalid result; no retry"); goto done; }
    if (!free_root(fd,r->operations[0].object,false,&r->operations[3])) { fail(r,"second ROOT free failed or returned an invalid result; no retry"); goto done; }
    r->success=true;
 done:
    /* close may itself report an error after consuming fd; never retry it.
     * Its return does not certify synchronous completion of backend cleanup. */
    if (close(fd)==0) r->closed=true;
    else { r->close_error=errno; r->success=false; fail(r,"control close failed; descriptor close is not retried"); }
}

static void json_string(FILE *file, const char *value)
{
    fputc('"',file);
    for (const unsigned char *p=(const unsigned char *)value; *p; ++p) {
        if (*p=='"' || *p=='\\') { fputc('\\',file); fputc(*p,file); }
        else if (*p<0x20) fprintf(file,"\\u%04x",*p);
        else fputc(*p,file);
    }
    fputc('"',file);
}
#define BOOL(x) ((x) ? "true" : "false")
static int write_report(int fd, const struct options *o, const struct result *r)
{
    FILE *file=fdopen(fd,"w");
    if (file==NULL) { close(fd); return -1; }
    fprintf(file,"{\n  \"schema\": \"nvidia-hybrid-frontend-canary-v1\",\n  \"mode\": \"%s\",\n  \"qualification\": \"%s\",\n",o->execute ? "execute" : "preflight-only",
        r->success ? "ROOT-only-control-transactions-passed" : (r->preflight && !o->execute ? "preflight-passed-not-executed" : "not-validated"));
    fprintf(file,"  \"legacy_pci\": "); json_string(file,o->legacy_pci);
    fprintf(file,",\n  \"open_pci\": "); json_string(file,o->open_pci);
    fprintf(file,",\n  \"expected_kernel_release\": "); json_string(file,o->kernel);
    fprintf(file,",\n  \"error\": "); json_string(file,r->error);
    fprintf(file,",\n  \"preflight\": {\"passed\": %s, \"kernel_matches\": %s, \"legacy_parameter\": %s, \"open_parameter\": %s, \"legacy_driver\": %s, \"open_driver\": %s, \"legacy_module\": %s, \"open_module\": %s, \"enabled\": %s, \"misc_identity\": %s},\n",
        BOOL(r->preflight),BOOL(r->kernel_matches),BOOL(r->legacy_parameter),BOOL(r->open_parameter),BOOL(r->legacy_driver),BOOL(r->open_driver),BOOL(r->legacy_module),BOOL(r->open_module),BOOL(r->enabled),BOOL(r->misc_identity));
    fprintf(file,"  \"control_opened\": %s,\n  \"control_close_succeeded\": %s,\n  \"control_close_errno\": %d,\n  \"execution_attempted\": %s,\n  \"root_transactions_passed\": %s,\n  \"cuda_validated\": false,\n  \"gpu_kernels_executed\": false,\n  \"uvm_validated\": false,\n  \"backend_cleanup_synchronous\": false,\n  \"operations\": [\n",
        BOOL(r->opened),BOOL(r->closed),r->close_error,BOOL(r->executed),BOOL(r->success));
    for (size_t i=0; i<4; ++i) {
        const struct operation *op=&r->operations[i];
        fprintf(file,"    {\"name\": \"%s\", \"attempted\": %s, \"success\": %s, \"syscall_return\": %d, \"errno\": %d, \"status\": %u, \"class\": %u, \"root\": %u, \"parent\": %u, \"object\": %u}%s\n",
            op->name,BOOL(op->attempted),BOOL(op->success),op->syscall_return,op->error,op->status,op->klass,op->root,op->parent,op->object,i==3 ? "" : ",");
    }
    fprintf(file,"  ]\n}\n");
    bool failed=ferror(file)!=0;
    if (fclose(file)!=0) failed=true;
    return failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    struct options options={0};
    struct result result={.operations={{.name="alloc-nvos21"},{.name="alloc-nvos64"},{.name="free-second-parent-root"},{.name="free-first-parent-zero"}}};
    dev_t device=0;
    int parsed=parse(argc,argv,&options);
    if (parsed!=0) {
        FILE *stream=parsed>0 ? stdout : stderr;
        fprintf(stream,"Usage: %s --legacy-pci dddd:bb:ss.f --open-pci dddd:bb:ss.f --output NEW.json [--dry-run | --execute] [--kernel-release EXPECTED]\nDefault: preflight only; never opens the control device. ROOT-only, no GPU/CUDA validation.\n",argv[0]);
        return parsed>0 ? 0 : 2;
    }
    /* Reserve a new report before attempting anything; never replace a file
     * or follow an output symlink. Access/mode/IO errors fail closed. */
    int output=open(options.output,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (output<0) { fprintf(stderr,"Cannot create a new canary report: %s\n",strerror(errno)); return 2; }
    if (preflight(&options,&result,&device) && options.execute)
        execute(&options,&result,device);
    int exit_code=result.success ? 0 : (result.preflight && !options.execute ? 0 : (options.execute && result.executed ? 1 : CANARY_SKIP));
    if (write_report(output,&options,&result)!=0) { fprintf(stderr,"Writing the canary report failed\n"); return 2; }
    return exit_code;
}
