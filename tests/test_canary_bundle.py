# SPDX-License-Identifier: MIT
"""Archive integrity tests on synthetic bytes; never execute a module/canary."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from unittest.mock import patch
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    path = ROOT / 'tools' / (name + '.py')
    if not path.is_file():
        raise AssertionError('canary bundle implementation missing: ' + name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class CanaryBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {}
        for name, data, mode in [('modules/test.ko', b'synthetic ELF placeholder', 0o644),
                                 ('bin/test', b'synthetic executable, never run', 0o755),
                                 ('licenses/notice.txt', b'original notice\n', 0o644)]:
            path = self.root / ('source-' + str(len(self.files))); path.write_bytes(data)
            self.files[name] = (path, mode)
        self.metadata = {'kernel_release': '7.0.0-38-generic', 'runtime_validated': False,
                         'qualification': 'compile-only-local-canary', 'redistribution_assessed': False}

    def create(self, name='bundle.tar.gz'):
        tool = load('package_hybrid_canary')
        path = self.root / name
        result = tool.create_bundle(self.files, self.metadata, path)
        return path, result

    def rewrite(self, source, mutate):
        with tarfile.open(source, 'r:gz') as tar:
            members = [(m, tar.extractfile(m).read()) for m in tar.getmembers()]
        members = mutate(members)
        output = self.root / 'modified.tar.gz'
        with tarfile.open(output, 'w:gz') as tar:
            for member, data in members:tar.addfile(member, io.BytesIO(data) if data else None)
        return output

    def test_reproducible_archive_and_standalone_read_only_verification(self):
        path, result = self.create()
        again, result2 = self.create('again.tar.gz')
        self.assertEqual(path.read_bytes(), again.read_bytes())
        self.assertEqual(result['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        verifier = load('verify_canary_bundle')
        checked = verifier.verify_bundle(path, result['sha256'], '7.0.0-38-generic')
        self.assertEqual(checked['qualification'], 'integrity-verified-against-expected-sha256')
        self.assertFalse(checked['runtime_validated'])
        self.assertEqual(checked['files_verified'], 3)
        script = self.root / 'verify.py'; shutil.copy2(ROOT / 'tools/verify_canary_bundle.py', script)
        cli = subprocess.run([sys.executable, '-I', str(script), str(path), '--sha256', result['sha256'],
                              '--kernel-release', '7.0.0-38-generic'], cwd=self.root,
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)['files_verified'], 3)
        with tarfile.open(path, 'r:gz') as tar:
            for member in tar.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertTrue(member.isfile())
                self.assertEqual(member.uname, '')

    def test_wrong_hash_or_kernel_and_untrusted_manifest_are_distinct(self):
        path, result = self.create(); verify = load('verify_canary_bundle').verify_bundle
        self.assertEqual(verify(path)['qualification'], 'self-consistent-untrusted-manifest')
        for digest, kernel in [('0'*64, None), (result['sha256'], 'different-kernel')]:
            with self.subTest(digest=digest, kernel=kernel), self.assertRaises(ValueError):verify(path,digest,kernel)

    def test_valid_tar_padding_at_every_record_block_position(self):
        # TAR writes two mandatory zero blocks, then aligns to a 20-block
        # record. Padding can exceed one record when only one block remained.
        source=self.files['modules/test.ko'][0]
        for blocks in range(21):
            source.write_bytes(b'x'*(blocks*512))
            with self.subTest(blocks=blocks):
                path,result=self.create('padding-'+str(blocks)+'.tar.gz')
                checked=load('verify_canary_bundle').verify_bundle(path,result['sha256'])
                self.assertEqual(checked['files_verified'],3)

    def test_expected_digest_is_bound_to_the_stream_actually_parsed(self):
        good, result = self.create()
        self.files['modules/test.ko'][0].write_bytes(b'different payload, never approved')
        other, _ = self.create('other.tar.gz')
        verify = load('verify_canary_bundle').verify_bundle
        original_open = Path.open
        opens = []
        def substituted_open(path, *args, **kwargs):
            if path == good:
                opens.append(path)
                # Old hash / reopen-parse / rehash code observed good, evil,
                # good. Every digest was real; only the parsed stream differed.
                if len(opens) == 2:
                    return original_open(other, *args, **kwargs)
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', substituted_open):
            checked = verify(good, result['sha256'])
        self.assertEqual(checked['payload_bytes'], sum(p.stat().st_size for n,(p,m) in self.files.items())
                         - len(b'different payload, never approved') + len(b'synthetic ELF placeholder'))
        self.assertEqual(len(opens), 1, 'verification must consume one hashed compressed stream')

    def test_member_corruption_missing_extra_duplicates_and_links_are_rejected(self):
        path, result = self.create(); verify = load('verify_canary_bundle').verify_bundle
        def corrupt(rows):
            return [(m, b'X'*len(d) if m.name=='modules/test.ko' else d) for m,d in rows]
        def link(rows):
            member=tarfile.TarInfo('outside'); member.type=tarfile.SYMTYPE; member.linkname='/tmp/outside'
            return rows+[(member,b'')]
        def traversal(rows):
            member=tarfile.TarInfo('../outside'); member.size=1
            return rows+[(member,b'x')]
        def extra(rows):
            member=tarfile.TarInfo('unlisted'); member.size=1
            return rows+[(member,b'x')]
        cases=[corrupt, lambda rows:rows[1:], lambda rows:rows+[rows[-1]], link,traversal,extra]
        for mutate in cases:
            output=self.rewrite(path,mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):verify(output)
            output.unlink()
        self.assertFalse((self.root/'outside').exists())

    def test_invalid_manifest_versions_modes_and_resource_limits_fail(self):
        path,result=self.create(); verify=load('verify_canary_bundle').verify_bundle
        for field,value in [('schema','other'),('runtime_validated',True),('files',[]),('kernel_release','')]:
            def mutate(rows,field=field,value=value):
                out=[]
                for member,data in rows:
                    if member.name=='manifest.json':
                        obj=json.loads(data);obj[field]=value;data=json.dumps(obj).encode();member.size=len(data)
                    out.append((member,data))
                return out
            output=self.rewrite(path,mutate)
            with self.subTest(field=field),self.assertRaises(ValueError):verify(output)
            output.unlink()
        with self.assertRaises(ValueError):verify(path,max_total_bytes=4)
        with self.assertRaises(ValueError):verify(path,max_members=2)

    def test_gzip_footer_and_unaccounted_tail_are_not_ignored(self):
        path, result = self.create(); verify = load('verify_canary_bundle').verify_bundle
        raw = path.read_bytes()
        for name, data in [('no-footer', raw[:-8]), ('bad-crc', raw[:-8]+b'\x00'*8),
                           ('trailing-data', raw+gzip.compress(b'unlisted payload',mtime=0))]:
            modified=self.root/name;modified.write_bytes(data)
            with self.subTest(name=name),self.assertRaises(ValueError):verify(modified)

    def test_producer_digest_mismatch_does_not_publish_partial_archive(self):
        tool=load('package_hybrid_canary');output=self.root/'new.tar.gz'
        wrong={name:'0'*64 for name in self.files}
        with self.assertRaises(ValueError):tool.create_bundle(self.files,self.metadata,output,wrong)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob('.canary-bundle-*')),[])

    def test_firmware_contract_rejects_branch_hash_and_runtime_drift(self):
        tool=load('package_hybrid_canary')
        rows=[{'request':name,'sha256':digest,'bytes':size,'path':'unused'}
              for name,(digest,size) in tool.FIRMWARE.items()]
        report={'schema':'nvidia-hybrid-canary-firmware-v1',
                'status':'acquired-original-firmware-data-only',
                'loaded_or_installed':False,'hardware_validated':False,'blob_executed':False,
                'system_firmware_modified':False,'firmware_blobs':rows,'license_files':[{}]}
        self.assertEqual(tool.firmware_contract(report),set(tool.FIRMWARE))
        for kind in ('request','sha256','bytes','runtime','duplicate','missing-license'):
            bad=json.loads(json.dumps(report))
            if kind=='request':bad['firmware_blobs'][0]['request']='nvidia/595/gsp_ga10x.bin'
            elif kind=='sha256':bad['firmware_blobs'][0]['sha256']='0'*64
            elif kind=='bytes':bad['firmware_blobs'][0]['bytes']+=1
            elif kind=='runtime':bad['loaded_or_installed']=True
            elif kind=='duplicate':bad['firmware_blobs'].append(bad['firmware_blobs'][0])
            else:bad['license_files']=[]
            with self.subTest(kind=kind),self.assertRaises(ValueError):tool.firmware_contract(bad)

    def test_queries_do_not_inherit_loader_or_kmod_options(self):
        tool=load('package_hybrid_canary')
        with patch.dict(os.environ,{'MODPROBE_OPTIONS':'--force','LD_PRELOAD':'/not/a/library','PYTHONPATH':'/untrusted'}):
            result=tool.query(['/usr/bin/env'])
        self.assertNotIn('MODPROBE_OPTIONS=',result)
        self.assertNotIn('LD_PRELOAD=',result)
        self.assertNotIn('PYTHONPATH=',result)
        self.assertIn('LC_ALL=C',result)

    def test_creation_preserves_existing_output_and_rejects_unsafe_inputs(self):
        tool=load('package_hybrid_canary');path=self.root/'existing';path.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):tool.create_bundle(self.files,self.metadata,path)
        self.assertEqual(path.read_bytes(),b'preserve')
        source=self.files['modules/test.ko'][0];link=self.root/'link';link.symlink_to(source)
        for files in ({'../bad':(source,0o644)}, {'safe':(link,0o644)}, {'safe':(source,0o777)},
                      {'manifest.json':(source,0o644)}):
            with self.subTest(files=files),self.assertRaises(ValueError):
                tool.create_bundle(files,self.metadata,self.root/'new.tar.gz')
        self.assertFalse((self.root/'new.tar.gz').exists())
