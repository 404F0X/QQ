import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'native' / 'primary_caller_bridge.c'
    header = source.with_suffix('.h')
    compiler = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe')
    vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
    sdk = Path('C:/Program Files (x86)/Windows Kits/10')
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    dll = output / 'primary_caller_bridge.dll'
    env_result = subprocess.run(f'cmd.exe /d /s /c ""{vcvars}" 10.0.26100.0 >nul && set"', capture_output=True, text=True)
    if env_result.returncode:
        (output / 'environment-failure.log').write_text(env_result.stderr, encoding='utf-8')
        raise SystemExit('x64 toolchain environment failed')
    env = os.environ.copy()
    for line in env_result.stdout.splitlines():
        key, sep, value = line.partition('=')
        if sep and key:
            env[key] = value
    command = [str(compiler), '/nologo', '/Brepro', '/LD', '/TC', '/std:c11', '/O2', '/W4', '/WX', '/GS', '/guard:cf', '/MD',
               str(source), '/Fo' + str(output / 'primary_caller_bridge.obj'), '/link', '/Brepro',
               '/guard:cf', '/OUT:' + str(dll), '/IMPLIB:' + str(output / 'primary_caller_bridge.lib'),
               'kernel32.lib', 'ntdll.lib']
    inputs = {'c_sha256': sha(source), 'header_sha256': sha(header), 'compiler_sha256': sha(compiler),
              'vcvars_sha256': sha(vcvars),
              'sdk_winnt_sha256': sha(sdk / 'Include/10.0.26100.0/um/winnt.h'),
              'sdk_ntdll_lib_sha256': sha(sdk / 'Lib/10.0.26100.0/um/x64/ntdll.lib')}
    attempt = 1 + len(list(output.glob('build-*.log')))
    (output / f'build-inputs-{attempt}.json').write_text(json.dumps(inputs, indent=2), encoding='utf-8')
    result = subprocess.run(command, env=env, cwd=output, capture_output=True, text=True)
    (output / f'build-{attempt}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise SystemExit(f'build failed: {result.returncode}; see build.log')
    manifest = dict(inputs, abi_version=1, architecture='AMD64', output_dll=str(dll),
                    compiler=str(compiler), sdk_version='10.0.26100.0', command=command,
                    debug_symbols='omitted; release unwind metadata retained', dll_sha256=sha(dll),
                    source_identity=hashlib.sha256(source.read_bytes() + header.read_bytes()).hexdigest())
    Path(str(dll) + '.manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'status': 'built', 'dll_sha256': manifest['dll_sha256']}))


if __name__ == '__main__':
    main()
