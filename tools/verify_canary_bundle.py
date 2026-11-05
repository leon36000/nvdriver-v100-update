#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a canary archive without extraction, device access or code execution.

Only an independently trusted expected SHA256 anchors the manifest. Without
one, success establishes self-consistency, not provenance/authenticity. Nothing
here validates module loading, CUDA or hardware operation.
"""
import argparse
import hashlib
import gzip
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

SCHEMA = 'nvidia-hybrid-canary-bundle-v1'
MAX_MEMBERS = 256
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


def digest_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda: f.read(1024*1024), b''): h.update(data)
    return h.hexdigest()


def safe_name(name):
    return (isinstance(name,str) and len(name)<=200 and
            str(PurePosixPath(name))==name and not name.startswith('/') and
            all(re.fullmatch(r'[A-Za-z0-9_.-]+', part) and part not in ('.','..')
                for part in name.split('/')))


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key: '+key)
        result[key]=value
    return result


class HashingReader:
    """Hash the compressed bytes consumed by gzip from this exact open file."""
    def __init__(self, stream):
        self.stream=stream; self.digest=hashlib.sha256()
    def read(self, size=-1):
        data=self.stream.read(size)
        self.digest.update(data)
        return data


class BoundedReader:
    def __init__(self, stream, limit):
        self.stream=stream; self.limit=limit; self.total=0; self.tail=b''
    def read(self, size):
        if size<0:raise ValueError('unbounded decompression refused')
        data=self.stream.read(size)
        self.total+=len(data)
        if self.total>self.limit:raise ValueError('decompressed archive budget exceeded')
        self.tail=(self.tail+data)[-10240:]
        return data


def verify_bundle(path, expected_sha256=None, expected_kernel=None, *,
                  max_members=MAX_MEMBERS, max_total_bytes=MAX_TOTAL_BYTES):
    if expected_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}',expected_sha256):
        raise ValueError('expected SHA256 must be lowercase hexadecimal')
    seen={}; manifest=None; total=0; payload_end=0
    try:
        # tarfile's gzip stream can stop at TAR EOF before checking the gzip
        # trailer. Drain a bounded gzip reader to validate CRC/truncation and
        # reject concatenated non-padding payloads, without extracting files.
        with Path(path).open('rb') as raw:
            hashed=HashingReader(raw)
            with gzip.GzipFile(fileobj=hashed) as zipped:
                reader=BoundedReader(zipped,max_total_bytes+max_members*512+20480)
                with tarfile.open(fileobj=reader,mode='r|',bufsize=512) as archive:
                    for member in archive:
                        if (member.offset!=payload_end or member.offset_data!=member.offset+512 or
                            len(seen)>=max_members or not safe_name(member.name) or
                            member.name in seen or not member.isfile() or member.pax_headers or
                            member.size<0 or member.size>MAX_MEMBER_BYTES or
                            member.mode not in (0o644,0o755) or member.uid!=0 or member.gid!=0 or
                            member.mtime!=0 or member.uname or member.gname):
                            raise ValueError('invalid, duplicate or oversized archive member: '+member.name)
                        payload_end=member.offset_data+((member.size+511)//512)*512
                        total+=member.size
                        if total>max_total_bytes:raise ValueError('archive byte budget exceeded')
                        stream=archive.extractfile(member)
                        if stream is None:raise ValueError('member contents unavailable')
                        h=hashlib.sha256(); remaining=member.size; chunks=[]
                        if member.name=='manifest.json' and member.size>MAX_MANIFEST_BYTES:
                            raise ValueError('manifest too large')
                        while remaining:
                            data=stream.read(min(1024*1024,remaining))
                            if not data:raise ValueError('truncated member')
                            remaining-=len(data);h.update(data)
                            if member.name=='manifest.json':chunks.append(data)
                        seen[member.name]={'sha256':h.hexdigest(),'bytes':member.size,'mode':member.mode}
                        if member.name=='manifest.json':
                            manifest=json.loads(b''.join(chunks),object_pairs_hook=unique_object)
                start=reader.total-len(reader.tail)
                if payload_end<start or any(reader.tail[max(0,payload_end-start):]):
                    raise ValueError('unaccounted TAR tail')
                while data:=reader.read(65536):
                    if any(data):raise ValueError('unaccounted payload after TAR EOF')
                if not (1024<=reader.total-payload_end<1024+10240) or reader.total%10240:
                    raise ValueError('invalid TAR terminator/padding')
    except (tarfile.TarError,OSError,UnicodeError,json.JSONDecodeError,EOFError) as error:
        raise ValueError('invalid archive: '+str(error)) from error
    if (not isinstance(manifest,dict) or manifest.get('schema')!=SCHEMA or
        manifest.get('runtime_validated') is not False or
        manifest.get('qualification')!='compile-only-local-canary' or
        manifest.get('redistribution_assessed') is not False or
        not isinstance(manifest.get('kernel_release'),str) or
        not re.fullmatch(r'[A-Za-z0-9._+-]{1,127}',manifest['kernel_release']) or
        not isinstance(manifest.get('files'),dict)):
        raise ValueError('invalid manifest contract')
    if expected_kernel is not None and manifest['kernel_release']!=expected_kernel:
        raise ValueError('target kernel mismatch')
    files=manifest['files']
    if not files or set(seen)!=(set(files)|{'manifest.json'}) or 'manifest.json'in files:
        raise ValueError('archive membership differs from manifest')
    for name,record in files.items():
        if (not safe_name(name) or not isinstance(record,dict) or
            set(record)!= {'sha256','bytes','mode'} or
            type(record['bytes']) is not int or type(record['mode']) is not int or
            not isinstance(record['sha256'],str) or
            not re.fullmatch(r'[0-9a-f]{64}',record['sha256']) or record!=seen[name]):
            raise ValueError('member digest/size/mode mismatch: '+name)
    # The expected digest covers exactly the compressed stream parsed above;
    # reopening the pathname for hashes would permit an ABA substitution.
    actual_hash=hashed.digest.hexdigest()
    if expected_sha256 is not None and actual_hash!=expected_sha256:
        raise ValueError('archive SHA256 mismatch')
    return {'schema':'nvidia-hybrid-canary-bundle-verification-v1','sha256':actual_hash,
            'qualification':'integrity-verified-against-expected-sha256' if expected_sha256 else
                            'self-consistent-untrusted-manifest',
            'kernel_release':manifest['kernel_release'],'files_verified':len(files),
            'payload_bytes':total-seen['manifest.json']['bytes'],
            'runtime_validated':False,'modules_loaded':False,'files_extracted':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--kernel-release')
    args=parser.parse_args()
    try:
        result=verify_bundle(args.archive,args.sha256,args.kernel_release)
    except (ValueError,OSError) as error:
        print(json.dumps({'qualification':'failed','error':str(error),'runtime_validated':False}))
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
