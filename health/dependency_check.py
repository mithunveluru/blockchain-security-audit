import sys
import os
import socket
import importlib
import subprocess
from dataclasses import dataclass

_REQUIRED_PACKAGES = ["flask", "flask_socketio", "eventlet", "numpy", "watchdog", "Crypto"]
_CAPTURE_PACKAGES  = ["scapy"]


@dataclass
class CheckResult:
    name: str
    ok: bool
    version: str | None = None
    error: str | None = None
    note: str | None = None


def _check_import(module: str, pkg_name: str = "") -> CheckResult:
    try:
        mod = importlib.import_module(module)
        try:
            import importlib.metadata as _meta
            version = _meta.version(pkg_name or module.replace("_", "-"))
        except Exception:
            version = getattr(mod, "__version__", None) or getattr(mod, "version", "unknown")
        return CheckResult(name=module, ok=True, version=str(version))
    except ImportError as e:
        return CheckResult(name=module, ok=False, error=str(e))
    except Exception as e:
        return CheckResult(name=module, ok=False, error=f"Unexpected error: {e}")


def check_scapy() -> CheckResult:
    try:
        import scapy
        import scapy.all as scapy_all
        version = getattr(scapy, "__version__", "unknown")
        ifaces = scapy_all.get_if_list()
        return CheckResult(
            name="scapy",
            ok=True,
            version=version,
            note=f"Interfaces visible: {', '.join(ifaces)}",
        )
    except ImportError as e:
        return CheckResult(
            name="scapy",
            ok=False,
            error=(
                f"ImportError: {e}\n"
                f"  Python executable: {sys.executable}\n"
                f"  sys.path includes: {[p for p in sys.path if 'site-packages' in p]}\n"
                f"  Fix: pip install scapy  (using the same pip that manages {sys.executable})"
            ),
        )
    except Exception as e:
        return CheckResult(name="scapy", ok=False, error=f"Unexpected: {e}")


def check_raw_socket_permission() -> CheckResult:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        s.close()
        return CheckResult(name="raw_socket_permission", ok=True, note="Raw sockets available without root")
    except PermissionError:
        python_real = os.path.realpath(sys.executable)
        return CheckResult(
            name="raw_socket_permission",
            ok=False,
            error="Permission denied for raw sockets",
            note=(
                "Packet capture requires elevated privileges. Options:\n"
                f"  1. Grant capability (run once, no sudo per run after):\n"
                f"       sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip {python_real}\n"
                f"       python enhanced_network_app.py\n"
                f"  2. sudo with the correct interpreter:\n"
                f"       sudo {python_real} enhanced_network_app.py\n"
                f"  3. Simulation mode:  ENABLE_SIMULATION_MODE=true python enhanced_network_app.py"
            ),
        )
    except Exception as e:
        return CheckResult(name="raw_socket_permission", ok=False, error=str(e))


def check_interface(interface: str) -> CheckResult:
    try:
        import scapy.all as scapy_all
        available = scapy_all.get_if_list()
    except Exception:
        try:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=3)
            available = [
                line.split(": ")[1].split("@")[0].strip()
                for line in result.stdout.splitlines()
                if line and line[0].isdigit()
            ]
        except Exception:
            available = []

    if interface in available:
        return CheckResult(name=f"interface:{interface}", ok=True, note=f"Available interfaces: {', '.join(available)}")
    else:
        return CheckResult(
            name=f"interface:{interface}",
            ok=False,
            error=f"Interface '{interface}' not found",
            note=f"Available: {', '.join(available) or 'none detected'}. Set NETWORK_INTERFACE env var.",
        )


def get_environment_info() -> dict:
    conda_env    = os.environ.get("CONDA_DEFAULT_ENV")
    conda_prefix = os.environ.get("CONDA_PREFIX")
    virtual_env  = os.environ.get("VIRTUAL_ENV")

    if virtual_env:
        env_type = "virtualenv"
        env_name = os.path.basename(virtual_env)
    elif conda_env and conda_env != "base":
        env_type = "conda"
        env_name = conda_env
    elif conda_prefix:
        env_type = "conda-base"
        env_name = "base"
    else:
        env_type = "system"
        env_name = "system"

    return {
        "python_executable": sys.executable,
        "python_real_path":  os.path.realpath(sys.executable),
        "python_version":    sys.version.split()[0],
        "env_type":          env_type,
        "env_name":          env_name,
        "conda_env":         conda_env,
        "conda_prefix":      conda_prefix,
        "virtual_env":       virtual_env,
        "user":              os.environ.get("USER", "unknown"),
        "uid":               os.geteuid(),
        "working_dir":       os.getcwd(),
        "site_packages":     [p for p in sys.path if "site-packages" in p],
    }


def check_interpreter_mismatch() -> CheckResult:
    missing = []
    for pkg in _REQUIRED_PACKAGES + _CAPTURE_PACKAGES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)

    if not missing:
        return CheckResult(
            name="interpreter_match", ok=True,
            note=f"All packages present in {sys.executable}",
        )

    candidates = []
    for path in [
        os.path.expanduser("~/miniconda3/bin/python"),
        os.path.expanduser("~/anaconda3/bin/python"),
        "/opt/conda/bin/python",
        "/usr/bin/python3",
    ]:
        real = os.path.realpath(path)
        if real != os.path.realpath(sys.executable) and os.path.exists(path):
            candidates.append(path)

    for candidate in candidates:
        try:
            check_cmd = f"import {', '.join(m for m in missing if m != 'Crypto')}"
            result = subprocess.run(
                [candidate, "-c", check_cmd],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return CheckResult(
                    name="interpreter_match", ok=False,
                    error=(
                        f"Packages {missing} are missing in current interpreter:\n"
                        f"  Current : {sys.executable}\n"
                        f"  Found in: {candidate}"
                    ),
                    note=(
                        f"Use the correct interpreter:\n"
                        f"  {candidate} enhanced_network_app.py\n"
                        f"Or with sudo (for packet capture):\n"
                        f"  sudo {os.path.realpath(candidate)} enhanced_network_app.py\n"
                        f"Or use run.sh which handles this automatically:\n"
                        f"  PYTHON={candidate} ./run.sh"
                    ),
                )
        except Exception:
            continue

    return CheckResult(
        name="interpreter_match", ok=False,
        error=f"Required packages {missing} not found in any known interpreter.",
        note=f"Install: {sys.executable} -m pip install {' '.join(missing)}",
    )


def check_blockchain_file(path: str) -> CheckResult:
    import json
    if not os.path.exists(path):
        return CheckResult(name="blockchain_file", ok=True, note=f"{path} does not exist — will be created on first run")
    try:
        with open(path) as f:
            data = json.load(f)
        return CheckResult(name="blockchain_file", ok=True, note=f"{path}: {len(data)} blocks")
    except json.JSONDecodeError as e:
        return CheckResult(name="blockchain_file", ok=False, error=f"Corrupted blockchain JSON: {e}")
    except PermissionError as e:
        return CheckResult(name="blockchain_file", ok=False, error=f"Cannot read blockchain file: {e}")


def run_all(interface: str, chain_file: str) -> list[CheckResult]:
    env = get_environment_info()
    results = [
        CheckResult(
            name="python",
            ok=True,
            version=env["python_version"],
            note=(
                f"Executable : {env['python_executable']}\n"
                f"Real path  : {env['python_real_path']}\n"
                f"Environment: {env['env_type']} / {env['env_name']}\n"
                f"User       : {env['user']} (uid={env['uid']})\n"
                f"Working dir: {env['working_dir']}"
            ),
        ),
        check_interpreter_mismatch(),
        _check_import("flask", "flask"),
        _check_import("flask_socketio", "flask-socketio"),
        _check_import("eventlet", "eventlet"),
        check_scapy(),
        _check_import("numpy", "numpy"),
        _check_import("sklearn", "scikit-learn"),
        _check_import("watchdog", "watchdog"),
        _check_import("Crypto", "pycryptodome"),
        check_raw_socket_permission(),
        check_interface(interface),
        check_blockchain_file(chain_file),
    ]
    return results


def print_report(results: list[CheckResult], fail_on_errors: bool = True) -> bool:
    print("\n" + "=" * 70)
    print("STARTUP DEPENDENCY CHECK")
    print("=" * 70)

    all_ok = True
    for r in results:
        status = "OK  " if r.ok else "FAIL"
        version_str = f" [{r.version}]" if r.version else ""
        print(f"  [{status}] {r.name}{version_str}")
        if r.note:
            for line in r.note.splitlines():
                print(f"         {line}")
        if not r.ok and r.error:
            for line in r.error.splitlines():
                print(f"         ERROR: {line}")
            all_ok = False

    print("=" * 70)
    if not all_ok:
        print("  Some checks failed. See errors above.")
    else:
        print("  All checks passed.")
    print("=" * 70 + "\n")

    return all_ok


if __name__ == "__main__":
    import sys as _sys
    _interface = _sys.argv[1] if len(_sys.argv) > 1 else "wlp0s20f3"
    _chain = "network_blockchain.json"
    results = run_all(_interface, _chain)
    ok = print_report(results)
    _sys.exit(0 if ok else 1)
