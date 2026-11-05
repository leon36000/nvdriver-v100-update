# SPDX-License-Identifier: MIT
"""Cross-branch ROOT packet comparison tests over synthetic/archived JSON only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RootProtocolComparisonTests(unittest.TestCase):
    def load(self):
        path = ROOT / 'tools/compare_rm_root_protocols.py'
        self.assertTrue(path.is_file(), 'reproducible ROOT comparison tool is missing')
        spec = importlib.util.spec_from_file_location('root_protocol_comparison', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool

    @staticmethod
    def observer(child_exit):
        records = []
        for handle in (0x12340001, 0x12340002):
            entry = dict(layout='NVOS64', hRoot=0, hObjectParent=0,
                         hObjectNew=0, hClass=0, pAllocParms=0,
                         paramsSize=0, pRightsRequested=0, flags=0, status=0)
            output = dict(entry, hObjectNew=handle, hClass=65)
            records.append(dict(operation='alloc', packet_size=48,
                request=0xc030462b, entry=entry, exit=output,
                syscall_return=0, fd=7, tid=101))
        handle = 0x12340001
        free = dict(layout='NVOS00', hRoot=handle, hObjectParent=handle,
                    hObjectOld=handle, status=0)
        records.insert(1, dict(operation='free', packet_size=16,
            request=0xc0104629, entry=free, exit=dict(free),
            syscall_return=0, fd=7, tid=101))
        return dict(schema='nvidia-hybrid-rm-ioctl-observer-v1',
            trace_complete=True, errors=[], control_path='/dev/nvidiactl',
            architecture='x86_64', pointer_bits=64,
            nested_pointers_read=False, fd_identity_tracking=False,
            child_exit_code=child_exit, records=records)

    @classmethod
    def make_device(cls, role, pci, uuid):
        sm, name = ((70, 'Tesla V100-SXM2-16GB') if role == 'volta'
                    else (120, 'NVIDIA GeForce RTX 5080'))
        return dict(name=name, pci_bus_id=pci, uuid=uuid,
            compute_capability='7.0' if sm == 70 else '12.0', sm=sm,
            targeted=True, tested=True, architecture_kernel_passed=True,
            synchronous_passed=True, synchronous_sizes=[1, 31, 256, 4096, 65537],
            asynchronous_passed=True, asynchronous_sizes=[1, 31, 256, 4096, 65537],
            cleanup_passed=True, cleanup_errors=[])

    @classmethod
    def report_and_summary(cls, role, tmp):
        summarizer_path = ROOT / 'tools/summarize_rm_payloads.py'
        spec = importlib.util.spec_from_file_location('payload_summary_setup', summarizer_path)
        summarizer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(summarizer)
        child_exit = 0 if role == 'volta' else 77
        observer = cls.observer(child_exit)
        if role == 'volta':
            device = cls.make_device(role, '0000:00:05.0', 'GPU-V100')
            probe = dict(schema='nvidia-hybrid-probe-v2', status='control-passed',
                driver_api=13000, required_set_passed=True, required_sm=[70],
                missing_sm=[], devices=[device])
            report = dict(schema='nvidia-hybrid-pc3-v100-reference-transport-v1',
                exit_code=0, pc3_ssh_exit_code=0, remote=dict(
                    schema='nvidia-hybrid-pc3-v100-guest-reference-v1',
                    guest=dict(name=device['name'], uuid=device['uuid'], pci=device['pci_bus_id'],
                        driver_version='580.178.04', kernel_release='6.8.0-147-generic'),
                    probe=probe, probe_exit_code=0, observer_exit_code=0,
                    guest_cleanup_passed=True, payload_file_cleanup_passed=True,
                    qualification='v100-reference-report-contract-valid', ioctl_observation=observer))
        else:
            device = cls.make_device(role, '0000:02:00.0', 'GPU-RTX5080')
            probe = dict(schema='nvidia-hybrid-probe-v2', status='incomplete',
                driver_api=13020, required_set_passed=False, required_sm=[70, 120],
                missing_sm=[70], devices=[device])
            report = dict(schema='nvidia-hybrid-remote-selected-gpu-transport-v1',
                exit_code=77, ssh_exit_code=77, remote=dict(
                    schema='nvidia-hybrid-remote-selected-gpu-v1',
                    selected_nvidia_smi=dict(driver='595.99.02'),
                    qualification='rtx5080-report-contract-valid-hybrid-incomplete',
                    hardware_acceptance=dict(schema='nvidia-hybrid-hardware-acceptance-v2',
                        validation_errors=[], exit_code=77,
                        qualification='incomplete-hardware-missing',
                        kernel_release='7.0.0-38-generic',
                        host='pc3',
                        device_selection=dict(cuda_visible_devices=device['uuid'],
                            expected_pci_bus_id='00000000:02:00.0'),
                        probe=probe, ioctl_observation=dict(report=observer))))
        report_path = tmp / f'{role}-report.json'
        summary_path = tmp / f'{role}-summary.json'
        report_path.write_text(json.dumps(report))
        observer_summary = summarizer.summarize(observer)
        import hashlib
        report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        observer_summary['trace'] = {'path': str(report_path.resolve()), 'sha256': report_sha}
        observer_summary['tool_sha256'] = hashlib.sha256(summarizer_path.read_bytes()).hexdigest()
        summary_path.write_text(json.dumps(observer_summary))
        return report_path, summary_path

    def test_normalizes_bdf_and_proves_only_matching_root_slice(self):
        tool = self.load()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            volta_report, volta_summary = self.report_and_summary('volta', tmp)
            blackwell_report, blackwell_summary = self.report_and_summary('blackwell', tmp)
            result = tool.compare_reports(volta_report, volta_summary,
                blackwell_report, blackwell_summary)
        self.assertEqual(result['devices'][1]['pci'], '0000:02:00.0')
        self.assertTrue(result['comparison']['root_allocation_inputs_equal'])
        self.assertTrue(result['comparison']['root_free_shape_equal'])
        self.assertTrue(result['comparison']['all_observed_root_inputs_fit_bounded_broker_validation'])
        self.assertIn('prototype nonzero-hRoot mirrored request has not been observed',
                      result['interpretation'])
        self.assertFalse(result['comparison']['same_linux_instance'])
        self.assertFalse(result['devices'][1]['required_set_passed'])
        self.assertTrue(result['devices'][1]['selected_device_kernel_passed'])
        self.assertIn('same-process or same-Linux coexistence', result['not_proven'])
        self.assertEqual(result['devices'][1]['driver'], '595.99.02')
        self.assertEqual(len(result['tool']['sha256']), 64)

    def test_different_or_unsupported_blackwell_shape_is_reported_without_overclaim(self):
        tool = self.load()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            volta_report, volta_summary = self.report_and_summary('volta', tmp)
            blackwell_report, blackwell_summary = self.report_and_summary('blackwell', tmp)
            report = json.loads(blackwell_report.read_text())
            entry = report['remote']['hardware_acceptance']['ioctl_observation']['report']['records'][0]['entry']
            entry['flags'] = 1
            blackwell_report.write_text(json.dumps(report))
            spec = importlib.util.spec_from_file_location(
                'payload_summary_mismatch', ROOT / 'tools/summarize_rm_payloads.py')
            summarizer = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(summarizer)
            observer = report['remote']['hardware_acceptance']['ioctl_observation']['report']
            summary = summarizer.summarize(observer)
            import hashlib
            summary['trace'] = {'path': str(blackwell_report.resolve()),
                'sha256': hashlib.sha256(blackwell_report.read_bytes()).hexdigest()}
            summary['tool_sha256'] = hashlib.sha256(
                (ROOT / 'tools/summarize_rm_payloads.py').read_bytes()).hexdigest()
            blackwell_summary.write_text(json.dumps(summary))
            result = tool.compare_reports(volta_report, volta_summary,
                blackwell_report, blackwell_summary)
        self.assertFalse(result['comparison']['root_allocation_inputs_equal'])
        self.assertFalse(result['comparison']['all_observed_root_inputs_fit_bounded_broker_validation'])
        self.assertIn('exceeds the broker current bounded slice', result['interpretation'])

    def test_rejects_unverified_blackwell_device_or_exit_mismatch(self):
        tool = self.load()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            volta_report, volta_summary = self.report_and_summary('volta', tmp)
            blackwell_report, blackwell_summary = self.report_and_summary('blackwell', tmp)
            report = json.loads(blackwell_report.read_text())
            report['remote']['hardware_acceptance']['probe']['devices'][0]['tested'] = False
            blackwell_report.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'RTX 5080 device-level kernel reference'):
                tool.compare_reports(volta_report, volta_summary,
                    blackwell_report, blackwell_summary)

    def test_rejects_summary_that_does_not_pin_source_report_or_tool(self):
        tool = self.load()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            volta_report, volta_summary = self.report_and_summary('volta', tmp)
            blackwell_report, blackwell_summary = self.report_and_summary('blackwell', tmp)
            summary = json.loads(volta_summary.read_text())
            summary['trace']['sha256'] = '0' * 64
            volta_summary.write_text(json.dumps(summary))
            with self.assertRaisesRegex(ValueError, 'summary does not pin exact source report'):
                tool.compare_reports(volta_report, volta_summary,
                    blackwell_report, blackwell_summary)

    def test_rejects_observer_that_tracks_fd_identity_or_nested_pointers(self):
        tool = self.load()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            volta_report, volta_summary = self.report_and_summary('volta', tmp)
            report = json.loads(volta_report.read_text())
            report['remote']['ioctl_observation']['fd_identity_tracking'] = True
            volta_report.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'observer scope'):
                tool.compare_reports(volta_report, volta_summary,
                    *self.report_and_summary('blackwell', tmp))


if __name__ == '__main__':
    unittest.main()
