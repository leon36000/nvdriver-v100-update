# SPDX-License-Identifier: MIT
"""Execute the patched R580 character-device lifecycle with kernel API doubles.

These are source contracts on CPU, never module-load or coexistence evidence.
"""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / '.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
PATCH = ROOT / 'patches/r580.178.04/0004-private-open-chardev.patch'
SOURCE = 'NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/nv.c'


class PrivateChardevTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ARCHIVE.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != '060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8':
                raise AssertionError('pinned archive mismatch')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            cls.original = archive.extractfile(SOURCE).read().decode()
        path = cls.root / 'kernel-open/nvidia/nv.c'
        path.parent.mkdir(parents=True)
        path.write_text(cls.original)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                       cwd=cls.root, check=True, capture_output=True)
        cls.text = path.read_text()

    def compile_run(self, name, text, extra_flags=()):
        source = self.root / (name + '.c')
        binary = self.root / name
        source.write_text(text)
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-fsanitize=undefined', *extra_flags, str(source), '-o', str(binary)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_registration_unwinds_every_failure(self):
        start = self.text.index('static dev_t hybrid_chrdev_base;')
        end = self.text.index('static int __init nvidia_init_module', start)
        helpers = self.text[start:end]
        self.compile_run('lifecycle', r'''
#include <assert.h>
#include <string.h>
#include <errno.h>
typedef unsigned long dev_t;
#define MKDEV(major,minor) (((dev_t)(major)<<20)|(minor))
#define MAJOR(dev) ((unsigned)((dev)>>20))
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255
struct file_operations { int unused; };
struct cdev { struct file_operations *ops; };
static struct cdev nv_linux_devices_cdev, nv_linux_control_device_cdev;
static struct file_operations nvidia_fops;
static int fail_at, calls, reserved, regular, control, releases, deletes;
static unsigned assigned_major;
static int alloc_chrdev_region(dev_t *base,unsigned first,unsigned count,const char *name) {
    assert(first==0 && count==256 && strcmp(name,"hybrid580_open")==0);
    assert(!reserved && !regular && !control);
    if (++calls==fail_at) return -EBUSY;
    *base=MKDEV(assigned_major,0); reserved=1; return 0;
}
static void cdev_init(struct cdev *c,struct file_operations *ops) { c->ops=ops; }
static int cdev_add(struct cdev *c,dev_t dev,unsigned count) {
    assert(reserved && c->ops==&nvidia_fops && MAJOR(dev)==assigned_major);
    if (++calls==fail_at) return -ENOMEM;
    if (c==&nv_linux_devices_cdev) { assert(dev==MKDEV(assigned_major,0) && count==248); regular=1; }
    else { assert(c==&nv_linux_control_device_cdev && regular && dev==MKDEV(assigned_major,255) && count==1); control=1; }
    return 0;
}
static void cdev_del(struct cdev *c) {
    assert(reserved); ++deletes;
    if (c==&nv_linux_control_device_cdev) { assert(control); control=0; }
    else { assert(c==&nv_linux_devices_cdev && regular && !control); regular=0; }
}
static void unregister_chrdev_region(dev_t base,unsigned count) {
    assert(reserved && !regular && !control && base==MKDEV(assigned_major,0) && count==256);
    reserved=0; ++releases;
}
''' + helpers + r'''
static void check(int failure,unsigned major) {
    fail_at=failure; assigned_major=major;
    calls=reserved=regular=control=releases=deletes=0;
    assert(hybrid_chrdev_base==0);
    int result=hybrid_register_chrdevs();
    if(failure) {
        assert(result==(failure==1?-EBUSY:-ENOMEM));
        assert(!reserved && !regular && !control && hybrid_chrdev_base==0);
        assert(releases==(failure==1?0:1)); assert(deletes==(failure==3?1:0));
    } else {
        assert(result==0 && reserved && regular && control);
        assert(MAJOR(hybrid_chrdev_base)==major);
        hybrid_unregister_chrdevs();
        assert(!reserved && !regular && !control && hybrid_chrdev_base==0);
        assert(releases==1 && deletes==2);
    }
}
int main(void) {
    for(unsigned major=240;major<=241;++major)
        for(int failure=0;failure<=3;++failure) check(failure,major);
    return 0;
}
''')

    def test_actual_file_owner_minors_and_reference_lifetime(self):
        start = self.text.index('nv_file_private_t* NV_API_CALL nv_get_file_private(')
        end = self.text.index('int NV_API_CALL nv_get_event(', start)
        functions = self.text[start:end]
        self.compile_run('file_owner', r'''
#include <assert.h>
#include <stddef.h>
typedef unsigned long dev_t;
typedef int NvS32; typedef int NvBool;
typedef struct { int token; } nv_file_private_t;
typedef struct { nv_file_private_t nvfp; } nv_linux_file_private_t;
#define NV_API_CALL
#define NV_FALSE 0
#define NV_TRUE 1
#define MAJOR(dev) ((unsigned)((dev)>>20))
#define MINOR(dev) ((unsigned)((dev)&((1UL<<20)-1)))
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247
#define NV_FILE_INODE(file) ((file)->inode)
struct inode { dev_t i_rdev; };
struct file_operations { int unused; };
struct file { struct inode *inode; const struct file_operations *f_op; nv_linux_file_private_t *private_data; };
static struct file_operations nvidia_fops, foreign_fops;
static dev_t hybrid_chrdev_base;
static struct file *input;
static void *nv_linux_minor_num_table[248];
static unsigned refs, reads;
static struct file *fget(int fd) { (void)fd; if(input) ++refs; return input; }
static void fput(struct file *file) { assert(file==input && refs==1); --refs; }
static nv_linux_file_private_t *get_private(struct file *file) { ++reads; return file->private_data; }
#define NV_GET_LINUX_FILE_PRIVATE(file) get_private(file)
''' + functions + r'''
static void check(struct file *file,dev_t base,int ctl,int expected) {
    void *owner=(void*)123;
    input=file; hybrid_chrdev_base=base; refs=reads=0;
    nv_file_private_t *private=nv_get_file_private(1,ctl,&owner);
    if(expected) {
        assert(private==&file->private_data->nvfp && owner==file);
        assert(refs==1 && reads==1);
        nv_put_file_private(owner); assert(refs==0);
    } else {
        assert(private==NULL && owner==(void*)123 && refs==0 && reads==0);
    }
}
int main(void) {
    nv_linux_file_private_t data={{42}};
    struct inode inode={240UL<<20};
    struct file own={&inode,&nvidia_fops,&data};
    nv_linux_minor_num_table[0]=&data; nv_linux_minor_num_table[247]=&data;
    unsigned minors[]={0,1,247,248,254,255};
    for(unsigned i=0;i<sizeof(minors)/sizeof(minors[0]);++i) {
        unsigned minor=minors[i]; inode.i_rdev=(240UL<<20)|minor;
        check(&own,240UL<<20,1,minor==255);
        check(&own,240UL<<20,0,minor==0 || minor==247);
    }
    inode.i_rdev=(195UL<<20)|255; check(&own,240UL<<20,1,0);
    inode.i_rdev=(240UL<<20)|255; own.f_op=&foreign_fops;
    check(&own,240UL<<20,1,0); own.f_op=&nvidia_fops;
    check(&own,0,1,0); check(NULL,240UL<<20,1,0);
    own.inode=NULL; check(&own,240UL<<20,1,0);
    return 0;
}
''', extra_flags=('-Wno-sign-compare',))  # Unmodified vendor int loop vs Linux unsigned MINOR.

    def test_source_init_exit_and_public_alias_removed(self):
        self.assertNotIn('NV_MAJOR_DEVICE_NUMBER', self.text)
        self.assertNotIn('MODULE_ALIAS_CHARDEV_MAJOR', self.text)
        self.assertNotIn('register_chrdev_region(', self.text.replace('unregister_chrdev_region(', ''))
        self.assertEqual(self.text.count('rc = hybrid_register_chrdevs();'), 1)
        self.assertEqual(self.text.count('    hybrid_unregister_chrdevs();'), 1)
        self.assertNotIn('partial_chrdev_exit:', self.text)
        init = self.text.split('static int __init nvidia_init_module', 1)[1].split('static void __exit', 1)[0]
        self.assertLess(init.index('rc = nv_uvm_init();'), init.index('rc = hybrid_register_chrdevs();'))
        self.assertIn('if (rc < 0)\n    {\n        goto no_chrdev_exit;\n    }', init)
        self.assertEqual(self.original.split('#include', 1)[0], self.text.split('#include', 1)[0])


if __name__ == '__main__':
    unittest.main()
