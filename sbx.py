#!/usr/bin/env python3
"""sbx — консольный VPN-клиент поверх sing-box: подписки, выбор сервера, автозапуск.

Движок — sing-box; sbx собирает конфиг и управляет systemd в Linux или задачей
Планировщика в Windows. Из подписки берутся лишь сами серверы
(outbound'ы): панели часто отдают конфиг в устаревшем формате полей, который
свежий sing-box уже не принимает, поэтому DNS, TUN и маршрутизация свои.

Форматы подписок (определяются сами):
  * sing-box JSON (полный конфиг или список outbound'ов);
  * Clash / mihomo YAML (секция proxies);
  * base64 или просто список URI: vless, vmess, trojan, ss, hysteria2/hy2, tuic, socks.

Режимы: TUN (весь трафик системы) + mixed SOCKS5/HTTP на 127.0.0.1:2080,
либо только прокси. LAN, WireGuard (10.8.0.0/24), docker и прочие частные сети
в туннель не идут, ответы WireGuard-сервера (:51820) и Caddy (:443) тоже —
иначе удалённый доступ отвалится.

Примеры:
  sbx sub add myvpn 'https://sub.example/xyz'    # добавить подписку и скачать
  sbx update                                     # обновить все подписки
  sbx ls                                         # серверы, ● — текущий
  sbx test                                       # задержка до всех серверов
  sbx pick   (или sbx use без аргумента)         # меню: ↑↓, пробел — пинг, Enter — выбрать
  sbx use 5 | sbx use германия | sbx use auto    # выбрать сервер
  sbx up | down | restart | status | log -f
  sbx enable | disable                           # автозапуск при загрузке
  sbx mode tun|proxy    sbx route ru|global
  sbx rule proxy example.ru | direct example.com | rm example.ru   # свои домены
  sbx rule via 're:Germany' geosite:google     # раздельная маршрутизация: список через свой сервер
  sbx rule proxy geosite:google-gemini         # …а это исключение — через основной
  sbx set exclude --add 203.0.113.7 | --rm 203.0.113.7             # элемент списка
  sbx add 'vless://…'                            # одиночный сервер без подписки
  sbx probe [-a]                                 # проверка рядом с другим VPN, без перехвата
"""
import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.4.0"

HOME = Path.home()
IS_WIN = os.name == "nt"


def axiom_mode(argv0=None):
    return os.environ.get("SBX_BRAND", "").lower() == "axiom" or axiom_mode_without_env(
        sys.argv[0] if argv0 is None else argv0)


def axiom_mode_without_env(argv0):
    return re.split(r"[/\\]", str(argv0))[-1].lower() in {"axiom", "axiom.exe", "axiom.py"}


def platform_paths(home, env, windows, axiom=False):
    """-> (каталог настроек, рабочий каталог, каталог ядра). AxiOm живёт отдельно от sbx."""
    override = env.get("SBX_HOME")
    if windows:
        roaming = Path(env.get("APPDATA") or home / "AppData/Roaming")
        local = Path(env.get("LOCALAPPDATA") or home / "AppData/Local")
        app, local = (roaming / "AxiOm" / "cli", local / "AxiOm" / "cli") if axiom else (
            roaming / "sbx", local / "sbx")
        config = Path(override or app)
        return config, config / "work" if override else local / "work", local / "core"
    if axiom:
        config = Path(override or home / ".config/axiom/cli")
        return config, config / "work" if override else home / ".local/state/axiom", None
    config = Path(override or home / ".config/sbx")
    return config, config / "work" if override else home / ".local/state/sbx", None


def sing_box_path(env, windows, core):
    return env.get("SBX_SING_BOX") or (str(core / "sing-box.exe") if windows else
                                       shutil.which("sing-box") or "/usr/bin/sing-box")


def identity_names(axiom):
    """Имена служб, задач и интерфейсов: у AxiOm свои, чтобы не пересекаться с sbx."""
    base = "axiom" if axiom else "sbx"
    return {"base": base, "unit": f"{base}.service", "update": f"{base}-update",
            "probe": f"{base}-probe", "probe_unit": f"{base}-probe.service",
            "tun": "axiom0" if axiom else "sbx0"}


def configure_identity(axiom, env=None, windows=None):
    global CONF_DIR, WORK_DIR, CORE_DIR, STATE_FILE, SUBS_DIR, RULESET_DIR, CONFIG_FILE, SING_BOX, LOG_FILE
    global BASE, UNIT, UPDATE, PROBE_IF, PROBE_UNIT, DEFAULT_TUN
    env = os.environ if env is None else env
    windows = IS_WIN if windows is None else windows
    CONF_DIR, WORK_DIR, CORE_DIR = platform_paths(HOME, env, windows, axiom)
    STATE_FILE = CONF_DIR / "state.json"
    SUBS_DIR = CONF_DIR / "subs"
    RULESET_DIR = CONF_DIR / "rulesets"
    CONFIG_FILE = CONF_DIR / "config.json"
    SING_BOX = sing_box_path(env, windows, CORE_DIR)
    LOG_FILE = WORK_DIR / "sing-box.log"
    names = identity_names(axiom)
    BASE, UNIT, UPDATE = names["base"], names["unit"], names["update"]
    PROBE_IF, PROBE_UNIT, DEFAULT_TUN = names["probe"], names["probe_unit"], names["tun"]


NO_ELEVATE = False
PARENT_INTERACTIVE = False   # повышенный процесс: родитель был интерактивным (скрытый флаг --elevated-interactive)
configure_identity(axiom_mode())
UNIT_DIR = Path("/etc/systemd/system")
# gvisor, а не system/mixed: system-стек принимает TCP через input ядра с TUN-интерфейса,
# а nftables (policy drop, разрешены lo/wg0/LAN) такие пакеты режет — TCP не работает.
STACK = "gvisor"

PROXY_TYPES = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2",
               "tuic", "socks", "http", "ssh", "shadowtls", "anytls", "naive"}

RULESETS = {
    "geoip-ru": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
    "geosite-category-ru": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
}

DEFAULT_EXCLUDE = [
    "10.0.0.0/8",        # WireGuard 10.8.0.0/24, docker wg-net 10.8.1.0/24
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",     # docker
    "192.168.0.0/16",    # LAN
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

AXIOM_MIXED_PORT = 2180
AXIOM_API_PORT = 9197

DEFAULT_STATE = {
    "subs": [],             # [{name, url, ua, hwid: bool}]
    "manual": [],           # outbound'ы, добавленные через `sbx add`
    "selected": "auto",
    "settings": {
        "mode": "tun",              # tun | proxy
        "route": "ru",              # ru — российское напрямую, global — всё через VPN
        "mixed_port": 2080,
        "api_port": 9097,
        "api_secret": "",
        "tun_name": "sbx0",
        "exclude": DEFAULT_EXCLUDE,
        "bypass_sports": ["udp:51820", "tcp:443"],   # ответы своих серверов — мимо TUN
        "bypass_users": [],         # весь трафик этих пользователей — мимо TUN (например, playit)
        "proxy_domains": [],        # домены (с поддоменами) — всегда через VPN, даже при route ru
        "direct_domains": [],       # домены (с поддоменами) — всегда напрямую
        "via_rules": [],            # [{to, items}] — домены/geosite через конкретный сервер или группу
        "dns_remote": "https://1.1.1.1/dns-query",
        "dns_direct": "77.88.8.8",
        "auto_exclude": "",         # regex: какие серверы не брать в auto
        "test_url": "https://www.gstatic.com/generate_204",
        "ua": "SFA/1.13 (sbx; sing-box)",   # ^SFA — Remnawave/Marzban отдают sing-box JSON
        "log_level": "info",
        "before_units": [],         # юниты, которые должны стартовать после VPN
    },
    "latency": {},          # tag -> ms (-1 = недоступен)
}


# ─── утилиты ──────────────────────────────────────────────────────────────────

def die(msg, code=1):
    print(f"sbx: {msg}", file=sys.stderr)
    sys.exit(code)


def warn(msg):
    print(f"⚠ {msg}", file=sys.stderr)


def is_old_cli_state(saved):
    """state.json прежнего Go-CLI AxiOm: {"subscription_url", "profile_path", "connected", ...}."""
    return isinstance(saved, dict) and "subscription_url" in saved and "settings" not in saved and "subs" not in saved


def migrate_old_cli_state(saved):
    """Один раз: сохраняет прежний state.json как state.old-cli.json и заводит новое состояние.

    URL подписки -> подписка «axiom» (серверы скачает ближайшая команда; ожидание хранится в `pending_fetch`,
    пока скачивание не удастся). profile_path (outbound'ы sing-box), если файл есть, -> локальная подписка
    «axiom-local» с серверами в кэше. profiles/ и workdir/ не трогаются. bypass_lan аналога не имеет.
    """
    backup = STATE_FILE.with_name("state.old-cli.json")
    if not backup.exists():
        shutil.copy2(STATE_FILE, backup)
    st = json.loads(json.dumps(DEFAULT_STATE))
    st["settings"].update(tun_name=DEFAULT_TUN, mixed_port=AXIOM_MIXED_PORT, api_port=AXIOM_API_PORT,
                          api_secret=secrets.token_hex(16))
    url = saved.get("subscription_url")
    if isinstance(url, str) and url.strip():
        st["subs"].append({"name": "axiom", "url": url.strip(), "hwid": True})
        st["pending_fetch"] = ["axiom"]
    path = saved.get("profile_path")
    if isinstance(path, str) and path.strip() and Path(path).is_file():
        sub = {"name": "axiom-local", "local_path": path}
        try:
            servers, _, _, meta = fetch_sub(st, sub)
        except (OSError, ValueError, TypeError):
            servers = []
        if servers:
            SUBS_DIR.mkdir(parents=True, exist_ok=True)
            write_private(sub_file("axiom-local"), json.dumps({"servers": servers, "meta": meta},
                                                              ensure_ascii=False, indent=1))
            st["subs"].append(sub)
    save_state(st)
    print("Перенесена подписка старого AxiOm CLI" if st["subs"] else
          "Состояние старого AxiOm CLI сохранено в state.old-cli.json (подписки в нём не было)", file=sys.stderr)
    return st


def load_state():
    st = json.loads(json.dumps(DEFAULT_STATE))
    if STATE_FILE.exists():
        saved = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if BASE == "axiom" and is_old_cli_state(saved):
            return migrate_old_cli_state(saved)
        settings = {**st["settings"], **saved.get("settings", {})}
        st.update(saved)
        st["settings"] = settings
    elif BASE == "axiom":
        # новое состояние AxiOm: свой интерфейс и свои порты, чтобы не занимать порты sbx
        st["settings"].update(tun_name=DEFAULT_TUN, mixed_port=AXIOM_MIXED_PORT, api_port=AXIOM_API_PORT)
    if not st["settings"]["api_secret"]:
        st["settings"]["api_secret"] = secrets.token_hex(16)
    return st


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        if not IS_WIN:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def save_state(st):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    if not IS_WIN:
        os.chmod(CONF_DIR, 0o700)
    write_private(STATE_FILE, json.dumps({key: value for key, value in st.items()
                                        if key not in {"_axiom", "_reload_windows"}},
                                       ensure_ascii=False, indent=2))


def hwid():
    """Как у Koala Clash / Happ-подобных клиентов: sha256(machine-id)[:16] — то же устройство в панели."""
    if IS_WIN:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                            access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            mid = winreg.QueryValueEx(key, "MachineGuid")[0]
    else:
        mid = Path("/etc/machine-id").read_text().strip()
    return hashlib.sha256(mid.encode()).hexdigest()[:16]


def os_version():
    if IS_WIN:
        return platform.version()
    try:
        rel = Path("/etc/os-release").read_text()
        name = re.search(r'^NAME="?([^"\n]+)', rel, re.M)
        return name.group(1) if name else "Linux"
    except OSError:
        return "Linux"


def b64decode(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_")).decode()
    except Exception:
        return None


OEM_TOOLS = {"schtasks", "whoami", "icacls", "powershell", "cmd", "taskkill", "netsh", "ipconfig"}


def console_encoding(cmd):
    """Windows: консольные утилиты пишут в OEM-странице, остальные (sing-box и т.п.) — в UTF-8."""
    exe = str(cmd[0] if isinstance(cmd, (list, tuple)) else cmd)
    name = re.split(r"[/\\]", exe)[-1].lower()
    return "oem" if name.removesuffix(".exe") in OEM_TOOLS else "utf-8"


def run(cmd, check=True, **kw):
    kw.setdefault("errors", "replace")
    if sys.platform == "win32":
        kw.setdefault("encoding", console_encoding(cmd))
    return subprocess.run(cmd, check=check, text=True, **kw)


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def sudo_cmd(*cmd):
    """Команда с правами root: от root — как есть, иначе через sudo."""
    return list(cmd) if is_root() else ["sudo", *cmd]


def systemctl(*args, sudo=False, check=True, capture=False):
    cmd = sudo_cmd("systemctl", *args) if sudo else ["systemctl", *args]
    return run(cmd, check=check, capture_output=capture)


def unit_prop(prop):
    r = systemctl("show", "-p", prop, "--value", UNIT, check=False, capture=True)
    return r.stdout.strip()


def is_active(st):
    if IS_WIN:
        return task_running() and api_up(st)
    return unit_prop("ActiveState") == "active"


def release_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": f"sbx/{__version__}"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def download_asset(asset, path, *, require_digest=False):
    digest = asset.get("digest")
    if (digest or require_digest) and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest or ""):
        raise ValueError("нет допустимой контрольной суммы SHA-256")
    url = asset["browser_download_url"]
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("загрузка релизов разрешена только по HTTPS")
    sha = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=30) as response, path.open("wb") as target:
        for block in iter(lambda: response.read(1024 * 1024), b""):
            sha.update(block)
            target.write(block)
    if digest and "sha256:" + sha.hexdigest() != digest.lower():
        raise ValueError("контрольная сумма SHA-256 не совпала")


def windows_arch():
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64",
            "x86": "386", "i386": "386"}.get(platform.machine().lower())
    if not arch:
        raise ValueError(f"неподдерживаемая архитектура Windows: {platform.machine()}")
    return arch


def install_core(directory):
    release = release_json("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
    version = release["tag_name"].removeprefix("v")
    filename = f"sing-box-{version}-windows-{windows_arch()}.zip"
    asset = next((entry for entry in release["assets"] if entry["name"] == filename), None)
    if not asset:
        raise ValueError(f"в релизе sing-box нет {filename}")
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        archive = Path(tmp) / "core.zip"
        download_asset(asset, archive, require_digest=True)
        with zipfile.ZipFile(archive) as source:
            files = {name: [entry for entry in source.namelist() if entry.rsplit("/", 1)[-1] == name]
                     for name in ("sing-box.exe", "libcronet.dll")}
            if len(files["sing-box.exe"]) != 1 or len(files["libcronet.dll"]) > 1:
                raise ValueError("неожиданный состав архива sing-box")
            for name, entries in files.items():
                if entries:
                    with source.open(entries[0]) as infile, (Path(tmp) / name).open("wb") as outfile:
                        shutil.copyfileobj(infile, outfile)
            for name in ("libcronet.dll", "sing-box.exe"):
                if files[name]:
                    os.replace(Path(tmp) / name, directory / name)
                elif (directory / name).exists():
                    (directory / name).unlink()
    return directory / "sing-box.exe"


def core_path():
    if IS_WIN and not os.environ.get("SBX_SING_BOX") and not Path(SING_BOX).exists():
        install_core(CORE_DIR)
    return SING_BOX


def cmd_core(st, a):
    if not IS_WIN:
        die("core install доступна в Windows; в Linux установите sing-box из пакета дистрибутива")
    if os.environ.get("SBX_SING_BOX"):
        die("задан SBX_SING_BOX; снимите переопределение для установки ядра")
    print(f"✓ ядро установлено: {install_core(CORE_DIR)}")


def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty()


def launch_command(argv):
    prefix = [] if getattr(sys, "frozen", False) else [str(Path(sys.argv[0]).absolute())]
    return [sys.executable, *prefix, *argv]


def windows_admin():
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


ELEVATED_ENV = {"--sbx-home": "SBX_HOME", "--axiom-home": "SBX_AXIOM_HOME", "--sing-box": "SBX_SING_BOX"}


def override_arguments(absolute=False):
    """Переопределения путей из окружения (SBX_HOME, SBX_AXIOM_HOME, SBX_SING_BOX) и марка -> скрытые флаги."""
    args = []
    for flag, key in ELEVATED_ENV.items():
        if value := os.environ.get(key):
            args += [flag, str(Path(value).expanduser().absolute()) if absolute else value]
    if axiom_mode():
        args.append("--axiom")
    return args


def elevated_arguments():
    """Скрытые флаги повышенного процесса: UAC не передаёт окружение, поэтому пути идут аргументами.

    Интерактивность родителя (stdin и stdout — терминал) передаётся явно: у дочернего процесса своя новая
    консоль, и по ней он не узнает, ждёт ли родитель человека или скрипт.
    """
    return ["--elevated-for", windows_user_sid(), "--elevated-interactive", "1" if interactive() else "0",
            *override_arguments()]


def wait_exit_code(handle, wait, exit_code, win_error):
    """Дождаться процесса и вернуть код выхода; сбой WinAPI — исключение (win_error() даёт OSError с текстом Windows)."""
    result = wait(handle)
    if result != 0:   # WAIT_OBJECT_0
        raise win_error() if result == 0xFFFFFFFF else OSError(f"WaitForSingleObject вернул {result:#x}")
    ok, code = exit_code(handle)
    if not ok:
        raise win_error()
    return code


def shell_execute_runas(exe, params, cwd):
    """ShellExecuteExW runas в обычном видимом окне консоли: ждёт завершения, возвращает код выхода (Windows)."""
    import ctypes
    from ctypes import wintypes

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40   # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb, info.lpFile, info.lpParameters, info.lpDirectory = "runas", exe, params, cwd
    info.nShow = 1      # SW_SHOWNORMAL: повышенный процесс виден и сам показывает ошибки
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not info.hProcess:
        raise OSError("ShellExecuteExW не вернул дескриптор процесса")

    def exit_code(handle):
        code = wintypes.DWORD(1)
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))), code.value

    try:
        return wait_exit_code(info.hProcess, lambda h: kernel32.WaitForSingleObject(h, 0xFFFFFFFF), exit_code,
                              lambda: ctypes.WinError(ctypes.get_last_error()))
    finally:
        kernel32.CloseHandle(info.hProcess)


def request_windows_admin(argv):
    if NO_ELEVATE:
        warn("нужны права администратора, а запуск с --no-elevate; не выполнено: " + " ".join(map(str, argv)))
        sys.exit(2)
    exe, *args = launch_command([*elevated_arguments(), *argv])
    if frozen_windows():
        os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    try:
        code = shell_execute_runas(exe, subprocess.list2cmdline(args), str(Path.cwd()))
    except OSError as e:
        die(f"не удалось выполнить с правами администратора (UAC): {e}")
    if code:
        sys.exit(code)
    print("✓ выполнено с правами администратора", flush=True)


def require_windows_admin(argv=None):
    if IS_WIN and not windows_admin():
        request_windows_admin(sys.argv[1:] if argv is None else argv)
        return False
    return True


RELEASES_URL = "https://api.github.com/repos/Xenon-Tetraoxide/SBX-VPN-Client/releases/latest"
UPDATE_PERIOD = 24 * 60 * 60
RELEASE_VERSION = re.compile(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9a-zA-Z.-]+))?(?:\+[0-9a-zA-Z.-]+)?$")


def version_key(version):
    match = RELEASE_VERSION.fullmatch(version.strip())
    if not match:
        raise ValueError(f"неизвестный формат версии: {version}")
    major, minor, patch, suffix = match.groups()
    prerelease = tuple((0, int(part)) if part.isdigit() else (1, part)
                       for part in suffix.split(".")) if suffix else ()
    return int(major), int(minor), int(patch), not suffix, prerelease


def latest_update():
    release = release_json(os.environ.get("SBX_RELEASES_URL") or RELEASES_URL)
    return release if version_key(release["tag_name"]) > version_key(__version__) else None


def frozen_windows():
    return IS_WIN and getattr(sys, "frozen", False)


def update_target():
    return Path(sys.executable if frozen_windows() else __file__).resolve()


def remove_old_exe():
    if frozen_windows():
        target = update_target()
        try:
            target.with_name(target.name + ".old").unlink(missing_ok=True)
        except OSError:
            pass


def replace_update(download, target, executable):
    mode = stat.S_IMODE(target.stat().st_mode)
    with tempfile.TemporaryDirectory(dir=target.parent) as directory:
        stage = Path(directory) / target.name
        shutil.copyfile(download, stage)
        if not IS_WIN:
            stage.chmod(mode)
        if not executable:
            os.replace(stage, target)
            return
        backup = target.with_name(target.name + ".old")
        os.replace(target, backup)
        try:
            os.replace(stage, target)
        except OSError:
            os.replace(backup, target)
            raise


def sudo_replace_update(download, target):
    mode = f"{stat.S_IMODE(target.stat().st_mode):04o}"
    temp = run(sudo_cmd("mktemp", "-p", str(target.parent), ".sbx-update.XXXXXXXX"),
               capture_output=True).stdout.strip()
    try:
        run(sudo_cmd("install", "-m", mode, "--", str(download), temp))
        run(sudo_cmd("mv", "-T", "--", temp, str(target)))
    finally:
        run(sudo_cmd("rm", "-f", "--", temp), check=False)


def install_update(release):
    executable = frozen_windows()
    name = "sbx-windows-amd64.exe" if executable else "sbx.py"
    asset = next((entry for entry in release["assets"] if entry["name"] == name), None)
    if not asset:
        raise ValueError(f"в релизе {release['tag_name']} нет {name}")
    target = update_target()
    with tempfile.TemporaryDirectory() as directory:
        download = Path(directory) / name
        download_asset(asset, download, require_digest=True)
        try:
            replace_update(download, target, executable)
        except PermissionError:
            if IS_WIN:
                if not require_windows_admin(["self-update", "--yes"]):
                    return
                raise
            sudo_replace_update(download, target)
    print(f"✓ установлена версия {release['tag_name']}: {target}")


def update_prompt(release):
    version = release["tag_name"].removeprefix("v")
    try:
        answer = input(f"Доступна новая версия sbx {version} (у вас {__version__}). "
                       "Установить сейчас? [Y/n] ").strip().lower()
    except EOFError:
        return False
    return answer in ("", "y", "yes", "д", "да")


def cmd_self_update(st, a):
    release = latest_update()
    if not release:
        print(f"Уже установлена актуальная версия sbx {__version__}")
    elif a.check:
        print(f"Доступна новая версия sbx {release['tag_name'].removeprefix('v')} (у вас {__version__})")
    elif a.yes or interactive() and update_prompt(release):
        install_update(release)
    elif not interactive():
        die("без терминала укажите --yes для установки или --check для проверки")


# Останавливают, снимают с автозапуска и удаляют службу: работают и при испорченном каталоге приложения AxiOm
SERVICE_ONLY_COMMANDS = {"down", "disconnect", "uninstall", "disable"}
NO_NOTICE_COMMANDS = {"self-update", "core", "up", "down", "disconnect", "restart", "connect", "status",
                      "install", "uninstall", "enable", "disable"}


def maybe_notice_update(st, a):
    if (not interactive() or getattr(a, "quiet", False) or a.cmd in NO_NOTICE_COMMANDS
            or os.environ.get("SBX_NO_UPDATE_CHECK") == "1" or os.environ.get("INVOCATION_ID")):
        return
    try:
        if not take_update_slot(st):
            return
        release = latest_update()
        if release and update_prompt(release):
            install_update(release)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as e:
        warn(f"не удалось проверить или установить обновление: {e}")
    except SystemExit as e:   # необязательное обновление не должно менять код уже выполненной команды
        warn(f"обновление не установлено (код {e.code})")


def take_update_slot(st):
    now = int(time.time())
    if now - st.get("last_update_check", 0) < UPDATE_PERIOD:
        return False
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    with (CONF_DIR / ".update-check.lock").open("a+b") as lock:
        try:
            if IS_WIN:
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fresh = load_state() if STATE_FILE.exists() else st
        if now - fresh.get("last_update_check", 0) < UPDATE_PERIOD:
            st["last_update_check"] = fresh["last_update_check"]
            return False
        st["last_update_check"] = fresh["last_update_check"] = now
        save_state(fresh)
        return True


def human_bytes(n):
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПиБ"


# ─── разбор серверов ──────────────────────────────────────────────────────────

class Unsupported(Exception):
    pass


def tls_block(security, sni=None, fp=None, alpn=None, insecure=False, pbk=None, sid=None):
    if security in (None, "", "none"):
        return None
    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if insecure:
        tls["insecure"] = True
    if alpn:
        tls["alpn"] = [a for a in (alpn if isinstance(alpn, list) else alpn.split(",")) if a]
    if security == "reality":
        if not pbk:
            raise Unsupported("reality без public key")
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid or ""}
        fp = fp or "chrome"
    if fp and fp not in ("none", ""):
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def transport_block(net, path=None, host=None, service_name=None, header_type=None):
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", ""):
        if header_type == "http":
            t = {"type": "http", "method": "GET"}
            if host:
                t["host"] = host.split(",")
            if path:
                t["path"] = path
            return t
        return None
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        m = re.search(r"[?&]ed=(\d+)", t["path"])
        if m:
            t["path"] = re.sub(r"[?&]ed=\d+", "", t["path"]) or "/"
            t["max_early_data"] = int(m.group(1))
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service_name or path or ""}
    if net in ("http", "h2"):
        t = {"type": "http"}
        if host:
            t["host"] = host.split(",")
        if path:
            t["path"] = path
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t
    raise Unsupported(f"транспорт {net} в sing-box не поддерживается")


def finish(out, tls=None, transport=None):
    if tls:
        out["tls"] = tls
    if transport:
        out["transport"] = transport
    return out


def split_hostport(netloc):
    """host:port с учётом [ipv6] и userinfo@."""
    hp = netloc.rsplit("@", 1)[-1]
    m = re.match(r"^\[([^\]]+)\]:(\d+)$", hp) or re.match(r"^([^:]+):(\d+)$", hp)
    if not m:
        raise Unsupported(f"не разобрать адрес {hp!r}")
    return m.group(1), int(m.group(2))


def parse_uri(uri):
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vmess":
        return parse_vmess(uri)
    if scheme == "ss":
        return parse_ss(uri)
    u = urllib.parse.urlsplit(uri)
    q = {k: v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
    name = urllib.parse.unquote(u.fragment) or None
    server, port = split_hostport(u.netloc)
    user = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else ""
    insecure = q.get("allowInsecure", q.get("insecure", "0")) in ("1", "true")

    if scheme in ("vless", "trojan"):
        out = {"type": scheme, "server": server, "server_port": port}
        if scheme == "vless":
            out["uuid"] = user
            if q.get("flow"):
                out["flow"] = q["flow"]
            out["packet_encoding"] = "xudp"
            default_sec = "none"
        else:
            out["password"] = user
            default_sec = "tls"
        sec = q.get("security", default_sec)
        tls = tls_block(sec, q.get("sni") or q.get("peer") or (server if sec == "tls" else None),
                        q.get("fp"), q.get("alpn"), insecure, q.get("pbk"), q.get("sid"))
        tr = transport_block(q.get("type"), q.get("path"), q.get("host"),
                             q.get("serviceName"), q.get("headerType"))
        return name, finish(out, tls, tr)

    if scheme in ("hysteria2", "hy2"):
        out = {"type": "hysteria2", "server": server, "server_port": port, "password": user}
        ports = q.get("mport") or q.get("ports")
        if ports:
            out["server_ports"] = [p.replace("-", ":") for p in ports.split(",")]
        if q.get("obfs") and q["obfs"] != "none":
            out["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
        out["tls"] = tls_block("tls", q.get("sni") or server, None, q.get("alpn") or "h3", insecure)
        return name, out

    if scheme == "tuic":
        uuid, _, password = user.partition(":")
        out = {"type": "tuic", "server": server, "server_port": port, "uuid": uuid,
               "password": password,
               "congestion_control": q.get("congestion_control", "bbr"),
               "udp_relay_mode": q.get("udp_relay_mode", "native")}
        out["tls"] = tls_block("tls", q.get("sni") or server, None, q.get("alpn") or "h3",
                               insecure or q.get("allow_insecure") == "1")
        return name, out

    if scheme in ("socks", "socks5"):
        out = {"type": "socks", "server": server, "server_port": port, "version": "5"}
        if user:
            decoded = user if ":" in user else (b64decode(user) or user)
            out["username"], _, out["password"] = decoded.partition(":")
        return name, out

    raise Unsupported(f"схема {scheme}:// не поддерживается")


def parse_vmess(uri):
    raw = b64decode(uri[len("vmess://"):])
    if not raw:
        raise Unsupported("vmess: не base64")
    j = json.loads(raw)
    out = {"type": "vmess", "server": j["add"], "server_port": int(j["port"]),
           "uuid": j["id"], "alter_id": int(j.get("aid") or 0),
           "security": j.get("scy") or "auto", "packet_encoding": "xudp"}
    tls = tls_block("tls" if j.get("tls") in ("tls", True) else None,
                    j.get("sni") or j.get("host") or None, j.get("fp"), j.get("alpn"),
                    str(j.get("allowInsecure", "")) in ("1", "true"))
    tr = transport_block(j.get("net"), j.get("path"), j.get("host"), j.get("path"), j.get("type"))
    return j.get("ps"), finish(out, tls, tr)


def parse_ss(uri):
    body = uri[len("ss://"):]
    body, _, frag = body.partition("#")
    name = urllib.parse.unquote(frag) or None
    body, _, query = body.partition("?")
    q = dict(urllib.parse.parse_qsl(query))
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        dec = b64decode(userinfo) if ":" not in userinfo else None
        method, _, password = (dec or userinfo).partition(":")
    else:  # legacy: base64(method:pass@host:port)
        dec = b64decode(body) or ""
        cred, _, hostport = dec.rpartition("@")
        method, _, password = cred.partition(":")
    server, port = split_hostport(hostport.rstrip("/"))
    out = {"type": "shadowsocks", "server": server, "server_port": port,
           "method": method, "password": password}
    if q.get("plugin"):
        plugin, _, opts = urllib.parse.unquote(q["plugin"]).partition(";")
        out["plugin"] = "obfs-local" if plugin in ("obfs-local", "simple-obfs") else plugin
        out["plugin_opts"] = opts
    return name, out


def from_clash(p):
    t = p.get("type")
    server, port = p.get("server"), int(p.get("port", 0))
    insecure = bool(p.get("skip-cert-verify"))
    name = p.get("name")
    ws, grpc, h2 = p.get("ws-opts") or {}, p.get("grpc-opts") or {}, p.get("h2-opts") or {}
    net = p.get("network")

    def tr():
        if net == "ws":
            return transport_block("ws", ws.get("path"), (ws.get("headers") or {}).get("Host"))
        if net == "grpc":
            return transport_block("grpc", service_name=grpc.get("grpc-service-name"))
        if net in ("h2", "http"):
            hosts = h2.get("host") or []
            return transport_block("http", h2.get("path"), ",".join(hosts) if hosts else None)
        if net == "httpupgrade":
            hu = p.get("http-upgrade-opts") or ws
            return transport_block("httpupgrade", hu.get("path"), (hu.get("headers") or {}).get("Host"))
        return transport_block(net)

    def tls(default_on):
        ro = p.get("reality-opts")
        sec = "reality" if ro else ("tls" if p.get("tls", default_on) else None)
        return tls_block(sec, p.get("servername") or p.get("sni") or (server if sec == "tls" else None),
                         p.get("client-fingerprint"), p.get("alpn"), insecure,
                         (ro or {}).get("public-key"), (ro or {}).get("short-id"))

    if t == "vless":
        out = {"type": "vless", "server": server, "server_port": port, "uuid": p["uuid"],
               "packet_encoding": "xudp"}
        if p.get("flow"):
            out["flow"] = p["flow"]
        return name, finish(out, tls(False), tr())
    if t == "vmess":
        out = {"type": "vmess", "server": server, "server_port": port, "uuid": p["uuid"],
               "alter_id": int(p.get("alterId", 0)), "security": p.get("cipher", "auto"),
               "packet_encoding": "xudp"}
        return name, finish(out, tls(False), tr())
    if t == "trojan":
        out = {"type": "trojan", "server": server, "server_port": port, "password": p["password"]}
        return name, finish(out, tls(True), tr())
    if t == "ss":
        out = {"type": "shadowsocks", "server": server, "server_port": port,
               "method": p["cipher"], "password": p["password"]}
        if p.get("plugin") == "obfs":
            po = p.get("plugin-opts") or {}
            out["plugin"] = "obfs-local"
            out["plugin_opts"] = f"obfs={po.get('mode', 'http')};obfs-host={po.get('host', '')}"
        elif p.get("plugin"):
            raise Unsupported(f"ss-плагин {p['plugin']}")
        return name, out
    if t == "hysteria2":
        out = {"type": "hysteria2", "server": server, "server_port": port,
               "password": p.get("password", "")}
        if p.get("ports"):
            out["server_ports"] = [x.replace("-", ":") for x in str(p["ports"]).split(",")]
        if p.get("obfs"):
            out["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password", "")}
        out["tls"] = tls_block("tls", p.get("sni") or server, None, p.get("alpn") or ["h3"], insecure)
        return name, out
    if t == "tuic":
        out = {"type": "tuic", "server": server, "server_port": port, "uuid": p["uuid"],
               "password": p.get("password", ""),
               "congestion_control": p.get("congestion-controller", "bbr"),
               "udp_relay_mode": p.get("udp-relay-mode", "native")}
        out["tls"] = tls_block("tls", p.get("sni") or server, None, p.get("alpn") or ["h3"], insecure)
        return name, out
    if t == "socks5":
        out = {"type": "socks", "server": server, "server_port": port, "version": "5"}
        if p.get("username"):
            out["username"], out["password"] = p["username"], p.get("password", "")
        return name, finish(out, tls(False) if p.get("tls") else None)
    raise Unsupported(f"clash-тип {t}")


def clean_outbound(o):
    o = {k: v for k, v in o.items() if k not in ("domain_strategy", "detour", "tag")}
    return o


def parse_subscription(text, *, preserve_detour=False):
    """-> (список (имя, outbound), список ошибок, формат)"""
    items, errors = [], []
    s = text.strip()
    if s.startswith(("{", "[")):
        try:
            j = json.loads(s)
            obs = j.get("outbounds", []) if isinstance(j, dict) else j
            if not isinstance(obs, list):
                return items, ["outbounds не является списком"], "sing-box json"
            for o in obs:
                if isinstance(o, dict) and o.get("type") in PROXY_TYPES:
                    outbound = clean_outbound(o)
                    if preserve_detour and isinstance(o.get("detour"), str) and o["detour"]:
                        outbound["detour"] = o["detour"]
                    items.append((o.get("tag"), outbound))
            return items, errors, "sing-box json"
        except json.JSONDecodeError:
            pass
    if re.search(r"^proxies\s*:", s, re.M):
        import yaml
        y = yaml.safe_load(s) or {}
        for p in y.get("proxies") or []:
            try:
                items.append(from_clash(p))
            except (Unsupported, KeyError, ValueError) as e:
                errors.append(f"{p.get('name')}: {e}")
        return items, errors, "clash yaml"
    fmt = "uri list"
    if "://" not in s:
        dec = b64decode(s)
        if dec and "://" in dec:
            s, fmt = dec, "base64"
    for line in s.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            items.append(parse_uri(line))
        except (Unsupported, KeyError, ValueError, json.JSONDecodeError) as e:
            label = urllib.parse.unquote(line.partition("#")[2]) or line.split("://")[0]
            errors.append(f"{label}: {e}")
    return items, errors, fmt


def is_stub(o):
    """Заглушки панелей (Remnawave без HWID и т.п.): 0.0.0.0:1."""
    return o.get("server") in ("0.0.0.0", "127.0.0.1", "") or o.get("server_port", 443) in (0, 1)


# ─── подписки ─────────────────────────────────────────────────────────────────

def sub_file(name):
    invalid = r'[<>:"/\\|?*\x00-\x1f]' if IS_WIN else r'[/\x00]'
    reserved = IS_WIN and re.fullmatch(r"CON|PRN|AUX|NUL|(?:COM|LPT)[1-9¹²³]", name.split(".", 1)[0], re.I)
    if not name or name in {".", ".."} or reserved or re.search(invalid, name):
        raise ValueError("имя подписки не должно содержать разделители пути: " + name)
    return SUBS_DIR / f"{name}.json"


def load_sub_cache(name):
    f = sub_file(name)
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {"servers": [], "meta": {}}


def fetch_sub(st, sub):
    if sub.get("local_path"):
        body = Path(sub["local_path"]).read_text(encoding="utf-8-sig")
        servers, errors, stubs, fmt = subscription_servers(body)
        return servers, errors, stubs, {"updated": int(time.time()), "format": fmt, "title": ""}
    headers = {"User-Agent": sub.get("ua") or st["settings"]["ua"], "Accept": "*/*"}
    if sub.get("hwid", True):
        headers.update({"x-hwid": hwid(), "x-device-os": "Windows" if IS_WIN else "Linux",
                        "x-ver-os": os_version(), "x-device-model": socket.gethostname()})
    req = urllib.request.Request(sub["url"], headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
        info = r.headers.get("subscription-userinfo", "")
        title = r.headers.get("profile-title", "")
    if title.startswith("base64:"):
        title = b64decode(title[7:]) or title
    meta = {"updated": int(time.time()), "title": title}
    for part in info.split(";"):
        k, _, v = part.strip().partition("=")
        if k and v.strip().isdigit():
            meta[k] = int(v)
    servers, errors, stubs, fmt = subscription_servers(body)
    meta["format"] = fmt
    return servers, errors, stubs, meta


def subscription_servers(body, *, app=False):
    items, errors, fmt = parse_subscription(body, preserve_detour=app)
    servers, stubs = [], 0
    for name, o in items:
        if is_stub(o):
            stubs += 1
            continue
        servers.append({"name": name if isinstance(name, str) and name else f"{o['type']} {o.get('server')}",
                        "outbound": o})
    return servers, errors, stubs, fmt


def update_subs(st, names=None, quiet=False):
    subs = [s for s in st["subs"] if not names or s["name"] in names]
    app = st.get("_axiom")
    profiles = [row for row in app["profiles"] if not names or app_sub_name(row) in names] if app else []
    missing = set(names or ()) - {sub["name"] for sub in subs} - {app_sub_name(row) for row in profiles}
    if missing:
        die(f"нет подписки {', '.join(sorted(missing))}")
    ok = update_app_profiles(app, profiles, quiet) if profiles else True
    for sub in subs:
        try:
            servers, errors, stubs, meta = fetch_sub(st, sub)
        except (urllib.error.URLError, OSError, ValueError, ImportError, TypeError) as e:
            warn(f"{sub['name']}: не скачалась ({e}), остаётся прошлый список")
            ok = False
            continue
        if not servers:
            hint = " — похоже на заглушки: панель требует HWID?" if stubs else ""
            warn(f"{sub['name']}: серверов нет ({meta['format']}){hint}, остаётся прошлый список")
            ok = False
            continue
        SUBS_DIR.mkdir(parents=True, exist_ok=True)
        write_private(sub_file(sub["name"]), json.dumps({"servers": servers, "meta": meta},
                                                        ensure_ascii=False, indent=1))
        if not quiet:
            extra = f", пропущено {len(errors)}" if errors else ""
            print(f"✓ {sub['name']}: {len(servers)} серверов ({meta['format']}{extra})")
            for e in errors:
                print(f"    пропущен {e}")
    update_rulesets(st, quiet)
    return ok


# ─── данные AxiOm ──────────────────────────────────────────────────────────────

AXIOM_UA_VERSION = "4.6.1"
AXIOM_DB_VERSION = 5
AXIOM_DB_TIMEOUT = 3.0


class AxiomDBUnavailable(ValueError):
    """База приложения AxiOm не годится для записи (версия схемы, недоступна)."""
AXIOM_HEADERS = {"profile-title", "content-disposition", "subscription-userinfo", "profile-update-interval",
                 "support-url", "profile-web-page-url", "enable-warp", "enable-fragment"}
AXIOM_PREFS = ("server_selector_country", "server_selector_protocol", "server_selector_transport")
AXIOM_AUTO = "__auto__"
AXIOM_FILE = "shared_preferences.json"


APP_LOCATION_MAX_AGE_MS = 24 * 3600 * 1000


def pid_alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if sys.platform == "win32":     # os.kill(pid, 0) на Windows шлёт Ctrl+C — только WinAPI
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259     # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def read_app_location():
    """<каталог CLI>/app-location.json, который пишет запущенное приложение; None — нет, битый или устарел."""
    try:
        data = json.loads((CONF_DIR / "app-location.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not is_v1(data.get("v")):
        return None
    for key in ("support_dir", "sync_dir", "prefs_file"):
        if not isinstance(data.get(key), str) or not os.path.isabs(data[key]):
            return None
    if data.get("prefs_prefix") not in ("flutter.", "portable."):
        return None
    ts = data.get("ts")
    if not is_int(ts) or not (pid_alive(data.get("pid")) or abs(time.time() * 1000 - ts) < APP_LOCATION_MAX_AGE_MS):
        return None
    return data


def is_v1(value):
    return is_int(value) and value == 1


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def axiom_locations():
    portable = []
    if IS_WIN:
        roaming = Path(os.environ.get("APPDATA") or HOME / "AppData/Roaming")
        installed = [roaming / "AxiOm/AxiOm", roaming / "AxiOm"]
        exe = Path(sys.executable if frozen_windows() else sys.argv[0]).absolute().parent
        portable = [exe / "hiddify_portable_data", exe.parent / "hiddify_portable_data"]
    else:
        share = Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local/share")
        installed = [share / "app.hiddify.com", share / "hiddify"]
    if override := os.environ.get("SBX_AXIOM_HOME"):
        root = Path(override).expanduser().absolute()
        if not (root / "db.sqlite").is_file():
            raise ValueError(f"в SBX_AXIOM_HOME нет db.sqlite: {root}; сначала запустите приложение AxiOm")
    else:
        located = read_app_location()
        if located and (Path(located["support_dir"]) / "db.sqlite").is_file():
            root = Path(located["support_dir"])     # приложение само сообщило, где оно (в т.ч. portable)
            return {"root": root, "prefs_path": Path(located["prefs_file"]), "prefix": located["prefs_prefix"],
                    "sync_dir": Path(located["sync_dir"])}
        root = next((path for path in [*portable, *installed] if (path / "db.sqlite").is_file()), None)
    if root is None:
        return None
    prefs = root / AXIOM_FILE
    is_portable = root.name == "hiddify_portable_data"
    if is_portable and not prefs.exists() and IS_WIN:
        prefs = next((path / AXIOM_FILE for path in installed if (path / AXIOM_FILE).is_file()),
                     installed[0] / AXIOM_FILE)
    return {"root": root, "prefs_path": prefs, "prefix": "portable." if is_portable else "flutter.",
            "sync_dir": root / "cli-sync"}


def read_axiom_prefs(path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    prefs = json.loads(text)
    if not isinstance(prefs, dict):
        raise ValueError("настройки AxiOm не являются JSON-объектом")
    return prefs


def axiom_db(app, mode):
    uri = (app["root"] / "db.sqlite").absolute().as_uri()
    db = sqlite3.connect(f"{uri}?mode={mode}", uri=True, timeout=AXIOM_DB_TIMEOUT)
    db.row_factory = sqlite3.Row
    return db


def empty_axiom_context():
    return {"root": None, "profiles": [], "prefs": {}, "prefix": "flutter.", "version": None}


def load_axiom_context():
    app = axiom_locations()
    if app is None:
        return empty_axiom_context()
    try:
        reload_axiom_profiles(app)
    except sqlite3.Error as exc:
        warn(f"база AxiOm недоступна ({exc}); профили приложения не используются")
        app["version"], app["profiles"] = None, []
    try:
        app["prefs"] = read_axiom_prefs(app["prefs_path"])
    except (OSError, ValueError) as exc:
        warn(f"настройки AxiOm не прочитаны ({exc}); файл не будет перезаписан")
        app["prefs"] = {}
    return app


def reload_axiom_profiles(app):
    with closing(axiom_db(app, "ro")) as db, db:
        db.execute("BEGIN")
        app["version"] = db.execute("PRAGMA user_version").fetchone()[0]
        try:
            app["profiles"] = [dict(row) for row in db.execute("SELECT * FROM profile_entries ORDER BY active DESC, name, id")]
        except sqlite3.OperationalError:
            if app["version"] == AXIOM_DB_VERSION:
                raise
            app["profiles"] = []
    if app["version"] != AXIOM_DB_VERSION:
        warn(f"база AxiOm версии {app['version']} — только чтение; для записи нужна версия {AXIOM_DB_VERSION}")


def app_writable(app):
    if app["version"] is None:
        raise AxiomDBUnavailable("база AxiOm недоступна (заблокирована или повреждена); запись невозможна")
    if app["version"] != AXIOM_DB_VERSION:
        raise AxiomDBUnavailable(f"база AxiOm версии {app['version']} открыта только для чтения; нужна версия {AXIOM_DB_VERSION}")


@contextmanager
def axiom_transaction(app):
    app_writable(app)
    with closing(axiom_db(app, "rw")) as db, db:
        db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version != AXIOM_DB_VERSION:
            raise AxiomDBUnavailable(f"база AxiOm версии {version} — только чтение; нужна версия {AXIOM_DB_VERSION}")
        yield db


def app_sub_name(row):
    return "app:" + row["name"]


def profile_file(app, profile_id):
    if str(uuid.UUID(profile_id)) != profile_id.lower():
        raise ValueError("недопустимый ID профиля AxiOm")
    return app["root"] / "configs" / f"{profile_id}.json"


def owned_file():
    return CONF_DIR / "axiom-profiles.json"


def owned_profile_ids():
    """ID профилей, созданных самим sbx (приложение этот список не видит)."""
    try:
        data = json.loads(owned_file().read_text(encoding="utf-8"))
        return {item for item in data.get("owned", []) if isinstance(item, str)}
    except (OSError, ValueError, AttributeError):
        return set()


def set_owned(profile_id, owned):
    ids = owned_profile_ids()
    ids.add(profile_id) if owned else ids.discard(profile_id)
    write_private(owned_file(), json.dumps({"owned": sorted(ids)}))


def app_db_key(app):
    """Короткий хеш пути базы приложения: кэши разных установок AxiOm не смешиваются."""
    path = str((app["root"] / "db.sqlite").absolute())
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]


APP_CACHE_VERSION = 2   # 2: группа сохраняется в порядке действующего ранга (1.3.0)


def app_cache_file(app, profile_id):
    """Кэш sbx для профиля приложения: каталог отдельно от подписок sbx, поэтому с их именами не пересекается."""
    if str(uuid.UUID(profile_id)) != profile_id.lower():
        raise ValueError("недопустимый ID профиля AxiOm")
    return SUBS_DIR / "axiom-app" / app_db_key(app) / f"{profile_id.lower()}.json"


def config_stamp(app, profile_id):
    """Ревизия конфига приложения (mtime, размер): изменился — кэш sbx устарел."""
    try:
        info = profile_file(app, profile_id).stat()
    except OSError:
        return None
    return [info.st_mtime_ns, info.st_size]


def write_app_cache(app, profile_id, config, group, row_last_update):
    """Кэш sbx: свежий список, состав и порядок группы приложения, собственное время обновления sbx."""
    write_private(app_cache_file(app, profile_id), json.dumps({
        "version": APP_CACHE_VERSION, "config": config, "group": group, "refreshed": int(time.time()),
        "row_last_update": row_last_update, "config_stamp": config_stamp(app, profile_id)},
        ensure_ascii=False))


def read_app_cache(app, row):
    """Действующий кэш профиля приложения или None: строка и файл конфига должны быть теми же, что при записи."""
    try:
        cache = json.loads(app_cache_file(app, row["id"]).read_text(encoding="utf-8"))
        group = cache["group"]
        if (cache["version"] == APP_CACHE_VERSION and cache["row_last_update"] == row.get("last_update") and isinstance(cache["config"], str)
                and cache["config_stamp"] == config_stamp(app, row["id"]) and isinstance(cache["refreshed"], int)
                and (group is None or isinstance(group, list) and all(isinstance(tag, str) for tag in group))):
            return cache
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def app_profile_text(app, row):
    """-> (конфиг, состав группы | None). У профилей приложения — кэш sbx, пока приложение не изменило профиль."""
    if row["id"] not in owned_profile_ids() and (cache := read_app_cache(app, row)):
        group = cache["group"]
        return cache["config"], None if group is None else {tag: index for index, tag in enumerate(group)}
    text = profile_file(app, row["id"]).read_text(encoding="utf-8-sig")
    return text, profile_group(text)


def app_cache(app, row):
    try:
        text, group = app_profile_text(app, row)
        servers, errors, _, _ = subscription_servers(text, app=True)
        if errors:
            warn(f"{app_sub_name(row)}: пропущено записей: {len(errors)}")
        return servers, group
    except (OSError, ValueError, TypeError, ImportError) as exc:
        warn(f"{app_sub_name(row)}: конфиг не прочитан ({exc})")
        return [], None


def profile_group(text):
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("outbounds"), list):
        return None
    outbounds = [entry for entry in document["outbounds"] if isinstance(entry, dict)]
    group_types = {"selector", "urltest"}
    tags = {entry["tag"] for entry in outbounds if entry.get("type") not in group_types
            and isinstance(entry.get("tag"), str)}
    groups = [[tag for tag in entry["outbounds"] if isinstance(tag, str) and tag in tags]
              for entry in outbounds if entry.get("type") in group_types
              and isinstance(entry.get("outbounds"), list)]
    group = max(groups, key=len, default=None)
    return {tag: index for index, tag in enumerate(group)} if group else None


def group_by_rank(group):
    """{тег: ранг} -> теги по возрастанию действующего ранга (для кэша) или None.

    У повторяющегося тега ранг — последний индекс, поэтому [A, B, A] даёт B, A; после перезагрузки из
    кэша порядок остаётся тем же, что без кэша.
    """
    return sorted(group, key=group.get) if group else None


def drift_date(timestamp):
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, ValueError, OSError):
        return None


def epoch_date(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace(" +", "+"))
            return int((parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp())
        except (ValueError, OverflowError, OSError):
            pass
    return None


def axiom_fetch(url):
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("профиль AxiOm должен иметь URL http:// или https://")
    os_name = "windows" if IS_WIN else "linux"
    ua = f"HiddifyNext/{AXIOM_UA_VERSION} ({os_name}) like ClashMeta v2ray sing-box"
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read().decode("utf-8-sig", "replace")
        headers = {}
        for key in AXIOM_HEADERS:
            values = [value for value in response.headers.get_all(key, []) if value]
            if values:
                headers[key] = values[0] if len(values) == 1 else values
    decoded = b64decode(body) or body
    for line in decoded.splitlines()[:10]:
        match = re.match(r"^(?:#|//)\s*([^:]+):\s*(.+)$", line)
        if match and (key := match[1].strip().lower()) in AXIOM_HEADERS:
            headers.setdefault(key, match[2].strip())
    return body, headers


def metadata_int(value):
    if isinstance(value, (str, int)) and str(value).isascii() and str(value).isdecimal() and len(str(value)) <= 19:
        number = int(value)
        if number <= 2 ** 63 - 1:
            return number
    return None


def is_url(value):
    parts = urllib.parse.urlsplit(value or "")
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def axiom_profile_metadata(url, headers, override, existing_override=None):
    def header(key):
        value = headers.get(key)
        return value if isinstance(value, str) else ""

    title = header("profile-title").strip()
    if title.startswith("base64:"):
        title = b64decode(title[7:]) or ""
    filename = re.search(r'filename="([^"]*)"', header("content-disposition"))
    parsed = urllib.parse.urlsplit(url or "")
    name = (override.get("name") or title or (filename[1] if filename else "") or parsed.fragment
            or re.sub(r"\.(?:json|ya?ml|txt)$", "", parsed.path.rsplit("/", 1)[-1]) or "Remote Profile")
    info = {}
    for field in header("subscription-userinfo").split(";"):
        key, _, value = field.strip().partition("=")
        info[key.strip()] = metadata_int(value.strip())
    upload, download, total = (info.get(key) for key in ("upload", "download", "total"))
    expire = None
    if upload is not None and download is not None:
        total = total or 920233720369
        expire = drift_date(info.get("expire") or 92233720368)
    else:
        upload = download = total = None
    gated = bool(header("subscription-userinfo"))   # как приложение: ссылки только вместе с userinfo
    web_page = header("profile-web-page-url") if gated and is_url(header("profile-web-page-url")) else None
    support = header("support-url") if gated and is_url(header("support-url")) else None
    interval = None if override.get("isAutoUpdateDisable") else (
        metadata_int(override.get("updateInterval")) or metadata_int(header("profile-update-interval")))
    if interval is not None and interval > (2 ** 63 - 1) // 3600:
        interval = None
    profile_override = dict(existing_override) if isinstance(existing_override, dict) else {}
    if header("enable-warp") == "true" or override.get("enableWarp") is True:
        profile_override.update({key: {"enable": True, "mode": "warp_over_proxy"} for key in ("warp", "warp2")})
    if header("enable-fragment") == "true" or override.get("enableFragment") is True:
        profile_override["tls-tricks"] = {"enable-fragment": True}
    return {"name": name, "last_update": drift_date(time.time()), "update_interval": interval and interval * 3600,
            "upload": upload, "download": download, "total": total, "expire": expire,
            "web_page_url": web_page, "support_url": support,
            "populated_headers": json.dumps(headers, ensure_ascii=False),
            "profile_override": json.dumps(profile_override, ensure_ascii=False)}


def app_profile_content(body):
    servers, errors, _, fmt = subscription_servers(body, app=True)
    if not servers:
        raise ValueError(f"в профиле нет поддерживаемых серверов ({fmt})")
    if errors:
        warn(f"профиль AxiOm: пропущено записей: {len(errors)}")
    outbounds = [{**server["outbound"], "tag": server["name"]} for server in servers]
    return json.dumps({"outbounds": outbounds}, ensure_ascii=False, indent=2)


def unique_profile_name(db, base, profile_id):
    taken = {row[0] for row in db.execute("SELECT name FROM profile_entries WHERE id != ?", (profile_id,))}
    name, index = base, 2
    while name in taken:
        name = f"{base}{index}"
        index += 1
    return name


def write_axiom_profile(app, *, name=None, url=None, local=None, current=None):
    """Создать профиль (sbx становится его владельцем) или обновить существующий.

    Профиль, созданный приложением, не перезаписывается: меняются только счётчики трафика и срок,
    а свежие серверы лежат в кэше sbx. Свои профили sbx пишет целиком, с копией `.sbx-prev`.
    """
    app_writable(app)
    profile_id = current["id"] if current else str(uuid.uuid4())
    owned = current is None or profile_id in owned_profile_ids()
    body, headers = (Path(local).read_text(encoding="utf-8-sig"), {}) if local else axiom_fetch(url)
    config = app_profile_content(body)
    path = profile_file(app, profile_id)
    previous = None
    changed = False
    marked = False
    try:
        with axiom_transaction(app) as db:
            existing = {}
            if current:
                row = db.execute("SELECT * FROM profile_entries WHERE id = ?", (profile_id,)).fetchone()
                if row is None or row["url"] != url or row["last_update"] != current["last_update"]:
                    raise ValueError("профиль изменён приложением AxiOm; повторите обновление")
                override = json.loads(row["user_override"] or "{}")
                try:
                    existing = json.loads(row["profile_override"] or "{}")
                except ValueError:
                    existing = {}
                result = row["name"]
            else:
                if url and db.execute("SELECT 1 FROM profile_entries WHERE instr(url, ?) > 0", (url,)).fetchone():
                    raise ValueError("такая подписка уже есть в AxiOm")
                override = {"version": 1, "name": name} if name else {}
            fields = axiom_profile_metadata(url, headers, override, existing)
            if not owned:
                # last_update принадлежит приложению: по нему оно решает, пора ли обновлять профиль.
                # Здесь меняем только трафик и срок; время обновления sbx живёт в его кэше.
                counters = {key: fields[key] for key in ("upload", "download", "total", "expire")}
                if fields["upload"] is None:
                    counters = {}
                if counters:
                    db.execute(f"UPDATE profile_entries SET {', '.join(key + ' = ?' for key in counters)} WHERE id = ?",
                               (*counters.values(), profile_id))
                write_app_cache(app, profile_id, config, group_by_rank(profile_group(body)),
                                row["last_update"])
            else:
                fields["name"] = unique_profile_name(db, fields["name"], profile_id)
                result = fields["name"]
                if current:
                    db.execute(f"UPDATE profile_entries SET {', '.join(key + ' = ?' for key in fields)} WHERE id = ?",
                               (*fields.values(), profile_id))
                else:
                    db.execute("UPDATE profile_entries SET active = 0 WHERE active = 1")
                    fields.update(id=profile_id, url=url, type="local" if local else "remote", active=1,
                                  user_override=json.dumps(override, ensure_ascii=False) if override else None)
                    db.execute(f"INSERT INTO profile_entries ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                               tuple(fields.values()))
                    set_owned(profile_id, True)
                    marked = True
                if path.exists():
                    previous = path.read_text(encoding="utf-8")
                    write_private(path.with_name(path.name + ".sbx-prev"), previous)
                write_private(path, config)
                changed = True
    except BaseException:
        if changed:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                write_private(path, previous)
        if marked:
            set_owned(profile_id, False)
        raise
    reload_axiom_profiles(app)
    return "app:" + result


def update_app_profiles(app, profiles, quiet):
    """Обновить удалённые профили приложения. Недоступная для записи база — предупреждение, не отказ."""
    ok = True
    for row in profiles:
        if row.get("type") != "remote":
            continue
        try:
            name = write_axiom_profile(app, url=row["url"], current=row)
            if not quiet:
                print(f"✓ {name}: обновлена")
        except (AxiomDBUnavailable, sqlite3.Error) as exc:
            warn(f"{app_sub_name(row)}: не обновлена ({exc}); остаётся прошлый список")
        except (OSError, ValueError, TypeError, ImportError) as exc:
            warn(f"{app_sub_name(row)}: не обновлена ({exc}); остаётся прошлый список")
            ok = False
    return ok


def remove_app_profile(app, name):
    with axiom_transaction(app) as db:
        row = db.execute("SELECT id, active FROM profile_entries WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise ValueError(f"нет подписки app:{name}")
        path = profile_file(app, row["id"])
        db.execute("DELETE FROM profile_entries WHERE id = ?", (row["id"],))
        if row["active"]:
            db.execute("UPDATE profile_entries SET active = 1 WHERE id = (SELECT id FROM profile_entries LIMIT 1)")
    path.unlink(missing_ok=True)
    path.with_name(path.name + ".sbx-prev").unlink(missing_ok=True)
    app_cache_file(app, row["id"]).unlink(missing_ok=True)
    set_owned(row["id"], False)
    reload_axiom_profiles(app)


def effective_route(st):
    app = st.get("_axiom")
    if app and app["root"]:
        return "ru" if app["prefs"].get(app["prefix"] + "region", "ru") == "ru" else "global"
    return st["settings"]["route"]


GEO_URL = {
    "geosite": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs",
    "geoip": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs",
}
GEO_RE = re.compile(r"^(geosite|geoip):([a-z0-9][a-z0-9!@._-]*)$")


def geo_tag(item):
    """«geosite:google» → «geosite-google»; обычный домен → None."""
    m = GEO_RE.match(item)
    return f"{m[1]}-{m[2]}" if m else None


def rule_items(st):
    """Все элементы правил: свои списки доменов и via_rules."""
    s = st["settings"]
    out = [x for k in DOMAIN_KEYS for x in s.get(k, [])]
    for v in s.get("via_rules", []):
        out += v["items"]
    return out


def wanted_rulesets(st):
    """tag -> url: rule-set'ы route ru и те, что упомянуты в правилах."""
    want = dict(RULESETS)
    for item in rule_items(st):
        m = GEO_RE.match(item)
        if m:
            want[f"{m[1]}-{m[2]}"] = GEO_URL[m[1]].format(m[2])
    return want


def update_rulesets(st, quiet=False, force=False, only=None):
    """Скачать устаревшие (старше 7 дней) rule-set'ы. -> список тегов, которые не скачались."""
    RULESET_DIR.mkdir(parents=True, exist_ok=True)
    failed = []
    for tag, url in wanted_rulesets(st).items():
        if only is not None and tag not in only:
            continue
        path = RULESET_DIR / f"{tag}.srs"
        if path.exists() and not force and time.time() - path.stat().st_mtime < 7 * 86400:
            continue
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            path.write_bytes(data)
            if not quiet:
                print(f"✓ rule-set {tag} ({human_bytes(len(data))})")
        except (urllib.error.URLError, OSError) as e:
            failed.append(tag)
            warn(f"rule-set {tag} не скачался: {e}")
    return failed


# ─── серверы и конфиг ─────────────────────────────────────────────────────────

def all_servers(st):
    """-> [{tag, outbound, source}] в стабильном порядке, теги уникальны."""
    out, seen = [], set()

    def add(name, o, source, **details):
        tag = name.strip() or "server"
        if tag in seen or tag in ("proxy", "auto", "direct") or tag.startswith(VIA_PREFIX):
            base, n = f"{tag} [{source}]", 2
            tag = base
            while tag in seen:
                tag, n = f"{base} #{n}", n + 1
        seen.add(tag)
        out.append({"tag": tag, "outbound": o, "source": source, **details})
        return tag

    if app := st.get("_axiom"):
        profiles = app["profiles"]
        profile = next((row for row in profiles if row.get("active")), profiles[0] if profiles else None)
        if profile:
            servers, group = app_cache(app, profile)
            aliases, entries = {}, []
            for server in servers:
                name = server["name"]
                tag = add(name, server["outbound"], app_sub_name(profile), display=name, app_profile=True,
                          app_group=group is None or name in group, app_order=group.get(name, 0) if group else 0)
                aliases.setdefault(name, tag)
                entries.append(out[-1])
            for entry in entries:
                if detour := entry["outbound"].get("detour"):
                    if detour not in aliases and detour != "direct":
                        raise ValueError(f"в профиле AxiOm не найден узел цепочки для «{entry['display']}»: {detour}")
                    entry["outbound"] = {**entry["outbound"], "detour": aliases.get(detour, detour)}

    for sub in st["subs"]:
        for s in load_sub_cache(sub["name"])["servers"]:
            add(s["name"], s["outbound"], sub["name"])
    for index, s in enumerate(st["manual"]):
        add(s["name"], s["outbound"], "manual", manual_index=index)
    return out


AXIOM_PROTOCOLS = {"vless": "VLESS", "hysteria2": "Hysteria2", "naive": "Naive", "shadowtls": "ShadowTLS"}
AXIOM_TRANSPORTS = {"ws": "WebSocket", "tcp": "Reality (TCP)", "hy2": "QUIC", "naive": "HTTP/2 TLS",
                    "stls": "ShadowTLS (TCP)"}
AXIOM_TOKENS = {"ws": ("vless", "ws"), "tcp": ("vless", "tcp"),
                **dict.fromkeys(("hy2", "hysteria2", "hysteria", "hy"), ("hysteria2", "hy2")),
                **dict.fromkeys(("naive", "http"), ("naive", "naive")),
                **dict.fromkeys(("stls", "shadowtls"), ("shadowtls", "stls"))}
AXIOM_TAG = re.compile(r"^(.*?)\s*\([^)]*\)\s*\[((?ai:[a-z0-9]+))\]\s*$")
AXIOM_COUNTRIES = {
    "netherlands": "NL", "france": "FR", "russia": "RU", "poland": "PL", "germany": "DE",
    "united states": "US", "usa": "US", "united kingdom": "GB", "uk": "GB", "finland": "FI",
    "sweden": "SE", "norway": "NO", "turkey": "TR", "japan": "JP", "singapore": "SG", "canada": "CA",
    "italy": "IT", "spain": "ES", "switzerland": "CH", "austria": "AT", "belgium": "BE", "czechia": "CZ",
    "czech republic": "CZ", "romania": "RO", "ukraine": "UA", "kazakhstan": "KZ", "hong kong": "HK",
    "taiwan": "TW", "south korea": "KR", "korea": "KR", "india": "IN", "brazil": "BR", "australia": "AU",
    "israel": "IL", "uae": "AE", "united arab emirates": "AE", "ireland": "IE", "denmark": "DK",
    "portugal": "PT", "hungary": "HU", "bulgaria": "BG", "serbia": "RS", "latvia": "LV", "lithuania": "LT",
    "estonia": "EE", "moldova": "MD", "georgia": "GE", "armenia": "AM", "azerbaijan": "AZ",
}


def axiom_classify(display):
    match = AXIOM_TAG.fullmatch(display.strip())
    if match and (country := match[1].strip()) and (tokens := AXIOM_TOKENS.get(match[2].lower())):
        return country, *tokens
    return None


def axiom_flag(country):
    code = AXIOM_COUNTRIES.get(country.strip().lower())
    return "".join(chr(ord(letter) + 127397) for letter in code) if code else "🏳️"


def axiom_options(servers):
    options = []
    from_app = any(server.get("app_profile") for server in servers)
    for server in sorted(servers, key=lambda item: item.get("app_order", 0)):
        if from_app and not server.get("app_group"):
            continue
        if group := axiom_classify(server.get("display", server["tag"])):
            options.append((group, server["tag"]))
    return options


def axiom_extras(servers, options=None):
    """Свои серверы sbx (подписки, ручные), которых нет в меню по странам; идут после серверов приложения.

    Дубликаты ключа «страна/протокол/транспорт» в меню не попадают, поэтому они тоже здесь.
    """
    options = axiom_options(servers) if options is None else options
    shown = {tag for _, tag in axiom_sorted(options)}
    return [server["tag"] for server in servers if not server.get("app_profile") and server["tag"] not in shown]


def axiom_menu(servers):
    """Единый упорядоченный список AxiOm -> (меню [(ключ, тег)], свои [тег]); по нему нумеруют все команды."""
    ordered = axiom_sorted(axiom_options(servers))
    return ordered, axiom_extras(servers, ordered)


def numbered_servers(st, servers):
    """Серверы в порядке номеров, которые показывает `ls`: меню AxiOm + свои, иначе обычный порядок."""
    if st.get("_axiom"):
        ordered, extras = axiom_menu(servers)
        if ordered:
            by_tag = {server["tag"]: server for server in servers}
            return [by_tag[tag] for _, tag in ordered] + [by_tag[tag] for tag in extras]
    return servers


def axiom_prefs_now(app):
    return [app.get("prefs", {}).get(app.get("prefix", "flutter.") + key) for key in AXIOM_PREFS]


def axiom_sorted(options):
    unique = {}
    for key, tag in options:
        unique.setdefault(key, tag)
    rank = list(AXIOM_PROTOCOLS)
    return sorted(unique.items(), key=lambda entry: (entry[0][0].encode("utf-16-be"),
                                                     rank.index(entry[0][1]), entry[0][2]))


def axiom_fastest(options, latencies):
    delays = [(latencies[tag], tag) for _, tag in options
              if isinstance(latencies.get(tag), int) and 0 < latencies[tag] < 65000]
    return min(delays, key=lambda entry: entry[0])[1] if delays else None


def axiom_chosen(app, options):
    country, protocol, transport = (app["prefs"].get(app["prefix"] + key) for key in AXIOM_PREFS)
    if not country or country == AXIOM_AUTO:
        return "auto"
    countries = [(key, tag) for key, tag in axiom_sorted(options) if key[0] == country]
    if not countries:
        return "auto"
    protocols = [(key, tag) for key, tag in countries if key[1] == protocol]
    group = protocols or [(key, tag) for key, tag in countries if key[1] == countries[0][0][1]]
    return next((tag for key, tag in group if key[2] == transport), group[0][1])


@contextmanager
def file_lock(path):
    """Блокировка между процессами sbx на отдельном файле; не зависит от базы приложения."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if sys.platform == "win32":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def axiom_write_selection(app, choice):
    if not app["root"]:
        return
    path = app["prefs_path"]
    with file_lock(path.with_name(path.name + ".sbx-lock")):   # замок привязан к самому файлу настроек
        prefs = read_axiom_prefs(path)
        keys = AXIOM_PREFS if choice else AXIOM_PREFS[:1]
        for key, value in zip(keys, choice or (AXIOM_AUTO,)):
            prefs[app["prefix"] + key] = value
        write_private(path, json.dumps(prefs, ensure_ascii=False))
    app["prefs"] = prefs


# ─── синхронизация с приложением AxiOm (cli-sync, протокол v2) ────────────────

SYNC_STALE_MS = 10_000      # сердцебиение app-state.json старше — приложение не запущено
SYNC_ACK_TIMEOUT = 15.0     # сколько ждать control-ack.json
SYNC_POLL = 0.2
START_LOCK_TTL_MS = 60_000  # start.lock моложе — идёт запуск движка
CONTROL_LOCK_TTL = 30.0     # control.lock старше — считается брошенным
CONTROL_LOCK_WAIT = 20.0
START_WAIT = 30.0           # сколько ждать чужого запуска перед отключением


def sync_dir():
    """Каталог cli-sync или None: не режим AxiOm, приложение не найдено."""
    if BASE != "axiom":
        return None
    try:
        app = axiom_locations()
    except (OSError, ValueError):
        return None
    return app["sync_dir"] if app else None


def read_sync_json(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def is_uuid4(value):
    try:
        return isinstance(value, str) and uuid.UUID(value).version == 4
    except ValueError:
        return False


def valid_app_state(data):
    if not data or not is_v1(data.get("v")) or not is_int(data.get("heartbeat")) or not isinstance(data.get("connected"), bool):
        return False
    if "connecting" in data and not isinstance(data["connecting"], bool):
        return False
    selection = data.get("selection")
    return selection is None or (isinstance(selection, dict) and all(isinstance(selection.get(k), str) for k in "cpt"))


def app_state(sync=None):
    """Состояние движка приложения или None (нет файла, битый, сердцебиение старше 10 с)."""
    sync = sync_dir() if sync is None else sync
    if sync is None:
        return None
    data = read_sync_json(sync / "app-state.json")
    if not valid_app_state(data) or abs(time.time() * 1000 - data["heartbeat"]) > SYNC_STALE_MS:
        return None
    return data


def app_engine_connected(sync=None):
    state = app_state(sync)
    return state if state and state["connected"] else None


def read_start_lock(sync):
    path = sync / "start.lock"
    data = read_sync_json(path)
    if data and data.get("owner") in ("app", "cli") and isinstance(data.get("id"), str) and is_int(data.get("ts")):
        return data
    try:       # файл есть, но пуст/не разобран (создаётся эксклюзивно, содержимое пишется вторым шагом): занят, возраст по mtime
        return {"owner": "unknown", "id": "", "ts": int(path.stat().st_mtime * 1000)}
    except OSError:
        return None


def start_lock_fresh(lock):
    return bool(lock) and abs(time.time() * 1000 - lock["ts"]) < START_LOCK_TTL_MS


def app_vpn_on(sync=None):
    """Приложение включено, подключается (connecting) или держит свежий start.lock -> словарь, иначе None."""
    sync = sync_dir() if sync is None else sync
    if sync is None:
        return None
    state = app_state(sync)
    if state and (state["connected"] or state.get("connecting")):
        return state
    lock = read_start_lock(sync)
    if lock and lock["owner"] != "cli" and start_lock_fresh(lock):
        return {"connected": False, "connecting": True, "selection": None, "rawTag": None}
    return None


def create_exclusive(path, payload):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload))


def lock_payload(owner):
    return {"owner": owner, "id": str(uuid.uuid4()), "ts": int(time.time() * 1000)}


@contextmanager
def start_reservation(sync):
    """Резерв запуска движка: start.lock создаётся эксклюзивно, снимается, когда движок поднят или запуск сорвался.

    Выдаёт True, если резерв наш (или каталога синхронизации нет); False — запуск уже идёт у другой стороны.
    """
    if sync is None or not sync.is_dir():
        yield True
        return
    path, payload = sync / "start.lock", lock_payload("cli")
    for _ in range(3):
        try:
            create_exclusive(path, payload)
            break
        except FileExistsError:
            lock = read_start_lock(sync)
            if start_lock_fresh(lock):
                yield False
                return
            path.unlink(missing_ok=True)     # брошенный или битый
    else:
        yield False
        return
    try:
        yield True
    finally:
        held = read_start_lock(sync)
        if held and held["id"] == payload["id"]:
            path.unlink(missing_ok=True)


@contextmanager
def control_lock(sync):
    """control.lock держится от записи control.json до ack или таймаута: две команды CLI не затирают друг друга."""
    path, payload = sync / "control.lock", lock_payload("cli")
    deadline = time.monotonic() + CONTROL_LOCK_WAIT
    while True:
        try:
            create_exclusive(path, payload)
            break
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except OSError:
                age = 0
            if age > CONTROL_LOCK_TTL:
                path.unlink(missing_ok=True)
                continue
            if time.monotonic() >= deadline:
                die("другая команда sbx уже обращается к приложению AxiOm; повторите позже")
            time.sleep(SYNC_POLL)
    try:
        yield
    finally:
        held = read_sync_json(path)
        if held and held.get("id") == payload["id"]:
            path.unlink(missing_ok=True)


def write_control(sync, cmd, selection=None):
    """Атомарно (tmp + rename) записывает control.json; возвращает id команды."""
    command = {"v": 1, "id": str(uuid.uuid4()), "ts": int(time.time() * 1000), "cmd": cmd}
    if selection is not None:
        command["selection"] = {"c": selection[0], "p": selection[1], "t": selection[2]}
    for attempt in range(5):
        try:
            write_private(sync / "control.json", json.dumps(command, ensure_ascii=False))
            break
        except PermissionError:      # Windows: приложение как раз читает файл
            if attempt == 4:
                raise
            time.sleep(0.05)
    return command["id"]


def valid_ack(ack, command_id):
    return (bool(ack) and is_v1(ack.get("v")) and is_uuid4(command_id) and ack.get("id") == command_id and isinstance(ack.get("ok"), bool)
            and is_int(ack.get("ts")))


def wait_ack(sync, command_id):
    deadline = time.monotonic() + SYNC_ACK_TIMEOUT
    while True:
        ack = read_sync_json(sync / "control-ack.json")
        if valid_ack(ack, command_id):
            return ack
        if time.monotonic() >= deadline:
            return None
        time.sleep(SYNC_POLL)


def send_app_command(sync, cmd, selection=None):
    """Отправляет команду приложению и ждёт подтверждения; ошибка или таймаут — выход с кодом 1."""
    with control_lock(sync):
        ack = wait_ack(sync, write_control(sync, cmd, selection))
    if ack is None:
        die(f"приложение AxiOm не подтвердило команду за {SYNC_ACK_TIMEOUT:g} с")
    if not ack["ok"]:
        die(f"приложение AxiOm отклонило команду: {ack.get('error') or 'ошибка'}")


def wait_app_start_finished(sync):
    """OFF при чужом запуске: ждёт (до 30 с), пока приложение закончит запуск."""
    deadline = time.monotonic() + START_WAIT
    while time.monotonic() < deadline:
        state = app_state(sync)
        lock = read_start_lock(sync)
        starting = (state and state.get("connecting")) or (lock and lock["owner"] != "cli" and start_lock_fresh(lock))
        if not starting:
            return
        time.sleep(SYNC_POLL)


def parse_select(text):
    parts = text.split("|")
    if len(parts) == 1:
        parts += ["", ""]
    if len(parts) != 3 or not parts[0]:
        die('--select: нужен вид "СТРАНА|ПРОТОКОЛ|ТРАНСПОРТ" (или __auto__)')
    return tuple(part.strip() for part in parts)


def resolve_select(st, text):
    """--select "C|P|T" -> (каноническая тройка приложения, тег сервера или "auto").

    __auto__ -> авто, p/t игнорируются; пустой p — первый протокол страны, пустой t — первый транспорт (c,p)
    в порядке приложения. Не из текущего меню — ошибка.
    """
    if not st.get("_axiom") or not st["_axiom"].get("root"):
        die("--select работает только в режиме AxiOm при найденном приложении")
    country, protocol, transport = parse_select(text)
    if country == AXIOM_AUTO:
        return (AXIOM_AUTO, "", ""), "auto"
    options = axiom_sorted(axiom_options(all_servers(st)))
    found = [(key, tag) for key, tag in options if key[0] == country]
    if not found:
        die(f"--select: страны «{country}» нет в меню; доступны: "
            + ", ".join(dict.fromkeys(key[0] for key, _ in options)))
    if protocol:
        found = [(key, tag) for key, tag in found if key[1] == protocol]
        if not found:
            die(f"--select: у «{country}» нет протокола «{protocol}»")
    else:
        found = [(key, tag) for key, tag in found if key[1] == found[0][0][1]]
    chosen_protocol = found[0][0][1]
    if transport:
        found = [(key, tag) for key, tag in found if key[2] == transport]
        if not found:
            die(f"--select: у «{country}|{chosen_protocol}» нет транспорта «{transport}»")
    key, tag = found[0]
    return key, tag


def remember_selection(app, triple):
    """Выбор, который сохранит приложение, — в память этого процесса (файл настроек пишет только приложение)."""
    for key, value in zip(AXIOM_PREFS, triple):
        app.setdefault("prefs", {})[app.get("prefix", "flutter.") + key] = value


def selected_server(st, servers):
    app = st.get("_axiom")
    if app and app["root"]:
        options = axiom_options(servers)
        if options:
            picked = st.get("axiom_extra")
            if (isinstance(picked, dict) and picked.get("tag") in axiom_extras(servers, options)
                    and picked.get("prefs") == axiom_prefs_now(app)):
                return picked["tag"]   # свой сервер, выбранный после последнего выбора в приложении
            return axiom_chosen(app, options)
    return st["selected"]


VIA_PREFIX = "via: "   # теги групп для via_rules вида re:… (имя сервера так начинаться не может)


def via_target(st, to, tags):
    """Цель правила via -> (тег outbound'а, urltest-группа или None).

    to: тег сервера, «re:REGEX» (urltest из подходящих серверов), auto, proxy или direct.
    Цели больше нет (подписка обновилась) — правило уходит в proxy, конфиг не ломается.
    """
    if to in ("proxy", "auto", "direct"):
        return to, None
    if to.startswith("re:"):
        rx = st["settings"].get("auto_exclude")
        try:
            found = [t for t in tags if re.search(to[3:], t, re.I)]
        except re.error:
            found = []
        members = [t for t in found if not (rx and re.search(rx, t, re.I))] or found
        if not members:
            warn(f"правило via {to}: подходящих серверов нет — идёт через proxy")
            return "proxy", None
        tag = VIA_PREFIX + to[3:]
        return tag, {"type": "urltest", "tag": tag, "outbounds": members,
                     "url": st["settings"]["test_url"], "interval": "5m", "tolerance": 50}
    if to in tags:
        return to, None
    warn(f"правило via: сервера «{to}» больше нет — идёт через proxy")
    return "proxy", None


def build_config(st, servers, *, tun=None, api_port=None, mixed_port=None, probe=False):
    cfg_s = st["settings"]
    tun = cfg_s["mode"] == "tun" if tun is None else tun
    tags = [s["tag"] for s in servers]
    rx = cfg_s.get("auto_exclude")
    options = axiom_options(servers) if st.get("_axiom") else []
    eligible = list(dict.fromkeys([*(tag for _, tag in options), *axiom_extras(servers, options)])) if options else tags
    auto = [tag for tag in eligible if not (rx and re.search(rx, tag, re.I))] or eligible
    if options:
        available = set(auto)
        best = axiom_fastest([(key, tag) for key, tag in options if tag in available], st["latency"])
        if best:
            auto.remove(best)
            auto.insert(0, best)
    selected = selected_server(st, servers)
    selected = selected if selected in tags else "auto"

    have = {t: (RULESET_DIR / f"{t}.srs") for t in RULESETS}
    have = {t: p for t, p in have.items() if p.exists()}
    ru = effective_route(st) == "ru" and have

    dns_remote = urllib.parse.urlsplit(cfg_s["dns_remote"])
    dns = {
        "servers": [
            {"type": dns_remote.scheme or "udp", "tag": "dns-remote",
             "server": dns_remote.hostname or cfg_s["dns_remote"],
             **({"path": dns_remote.path} if dns_remote.path else {})},
            {"type": "udp", "tag": "dns-direct", "server": cfg_s["dns_direct"]},
        ],
        "rules": [],
        "final": "dns-remote",
        "strategy": "ipv4_only",
    }
    rules = [
        {"action": "sniff"},
        {"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}],
         "action": "hijack-dns"},
        {"ip_cidr": [cfg_s["dns_direct"] + "/32"], "outbound": "direct"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    # Свои правила — раньше route ru: «.ru» из proxy_domains всё равно уходит в VPN, а google.ru
    # из via-правила — на свой сервер. Порядок: direct, proxy, via (первое совпадение побеждает),
    # поэтому исключение из большого списка — это тот же элемент в proxy/direct.
    used_sets, extra_out, extra_dns = [], [], []

    def add_rules(items, outbound, dns_server):
        sfx = sorted({norm_domain(d) for d in items if not geo_tag(d)} - {""})
        sets = []
        for t in dict.fromkeys(filter(None, map(geo_tag, items))):
            if (RULESET_DIR / f"{t}.srs").exists():
                sets.append(t)
            else:
                warn(f"rule-set {t} не скачан — правило пропущено (sbx update)")
        if sfx:
            dns["rules"].append({"domain_suffix": sfx, "server": dns_server})
            rules.append({"domain_suffix": sfx, "outbound": outbound})
        if sets:
            if site := [t for t in sets if t.startswith("geosite-")]:
                dns["rules"].append({"rule_set": site, "server": dns_server})
            rules.append({"rule_set": sets, "outbound": outbound})
            used_sets.extend(sets)

    add_rules(cfg_s.get("direct_domains", []), "direct", "dns-direct")
    add_rules(cfg_s.get("proxy_domains", []), "proxy", "dns-remote")
    for v in cfg_s.get("via_rules", []):
        out, group = via_target(st, v["to"], tags)
        if group and all(o["tag"] != out for o in extra_out):
            extra_out.append(group)
        if out == "direct":
            dns_server = "dns-direct"
        elif out in ("proxy", "auto"):
            dns_server = "dns-remote"
        else:
            # DNS через тот же сервер: иначе CDN отдаст адреса, ближайшие к основному выходу
            dns_server = f"dns-via-{len(extra_dns) + 1}"
            extra_dns.append({**dns["servers"][0], "tag": dns_server, "detour": out})
        add_rules(v["items"], out, dns_server)
    dns["servers"] += extra_dns

    if ru:
        if "geosite-category-ru" in have:
            dns["rules"].append({"rule_set": ["geosite-category-ru"], "server": "dns-direct"})
        rules.append({"domain_suffix": [".ru", ".su", ".xn--p1ai", ".рф"], "outbound": "direct"})
        rules.append({"rule_set": list(have), "outbound": "direct"})
        used_sets.extend(have)
    rule_sets = [{"type": "local", "tag": t, "format": "binary", "path": str(RULESET_DIR / f"{t}.srs")}
                 for t in dict.fromkeys(used_sets)]

    inbounds = []
    if probe:
        # TUN без auto_route: интерфейс есть, но ни маршрутов, ни ip rule — перехватывать нечего
        inbounds.append({"type": "tun", "tag": "tun-in", "interface_name": PROBE_IF,
                         "address": ["198.19.255.1/30"], "mtu": 9000,
                         "auto_route": False, "stack": STACK})
    elif tun:
        inbounds.append({
            "type": "tun", "tag": "tun-in", "interface_name": cfg_s["tun_name"],
            "address": ["198.18.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 9000,
            "auto_route": True, "strict_route": True, "stack": STACK,
            "route_exclude_address": cfg_s["exclude"],
        })
    inbounds.append({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                     "listen_port": mixed_port or cfg_s["mixed_port"]})

    outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto", *tags], "default": selected,
         "interrupt_exist_connections": True},
        {"type": "urltest", "tag": "auto", "outbounds": auto, "url": cfg_s["test_url"],
         "interval": "5m", "tolerance": 1 if options else 50},
        *extra_out,
        *({**s["outbound"], "tag": s["tag"]} for s in servers),
        {"type": "direct", "tag": "direct"},
    ]
    log = {"level": cfg_s["log_level"], "timestamp": True}
    if IS_WIN:
        log["output"] = str(LOG_FILE)
    return {
        "log": log,
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules, "rule_set": rule_sets, "final": "proxy",
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-direct"},
        },
        "experimental": {"clash_api": {
            "external_controller": f"127.0.0.1:{api_port or cfg_s['api_port']}",
            "secret": cfg_s["api_secret"], "default_mode": "rule"}},
    }


def check_config(path):
    r = run([core_path(), "check", "-c", str(path)], check=False, capture_output=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def apply(st, reload=True, quiet=False):
    """Собрать конфиг, проверить, записать; если движок работает — перечитать (SIGHUP)."""
    servers = all_servers(st)
    if not servers:
        die("серверов нет: добавьте подписку (sbx sub add) или сервер (sbx add)")
    text = json.dumps(build_config(st, servers), ensure_ascii=False, indent=2)
    old = CONFIG_FILE.read_text(encoding="utf-8") if CONFIG_FILE.exists() else None
    if text == old:
        return False
    if IS_WIN:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=CONF_DIR) as directory:
        tmp = Path(directory) / "config.json"
        write_private(tmp, text)
        ok, err = check_config(tmp)
        if not ok:
            die(f"sing-box отверг конфиг:\n{err}")
        os.replace(tmp, CONFIG_FILE)
    if reload and is_active(st):
        if IS_WIN:
            if windows_admin():
                publish_windows_config(st)
                service_action("restart")
            elif not quiet:
                if interactive():
                    st["_reload_windows"] = True
                else:
                    warn("конфиг сохранён; примените к задаче SYSTEM через sbx restart (UAC)")
        else:
            pid = int(unit_prop("MainPID") or 0)
            if pid:
                os.kill(pid, signal.SIGHUP)
                if not quiet:
                    print("↻ конфиг перечитан")
    return True


# ─── clash API ────────────────────────────────────────────────────────────────

def api(st, method, path, body=None, port=None, timeout=10):
    port = port or st["settings"]["api_port"]
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {st['settings']['api_secret']}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data) if data else None


def api_up(st, port=None):
    try:
        api(st, "GET", "/version", port=port, timeout=2)
        return True
    except (urllib.error.URLError, OSError):
        return False


def current_node(st):
    try:
        proxy = api(st, "GET", "/proxies/proxy")
        now = proxy.get("now")
        if now == "auto":
            return "auto → " + (api(st, "GET", "/proxies/auto").get("now") or "?")
        return now
    except (urllib.error.URLError, OSError, ValueError):
        return None


# ─── systemd ──────────────────────────────────────────────────────────────────

def unit_text(st):
    import pwd

    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or HOME.name
    rules = []
    for spec in st["settings"]["bypass_sports"]:
        proto, _, port = spec.partition(":")
        for fam in ("-4", "-6"):
            rules.append(f"{fam} rule %s priority 8990 ipproto {proto} sport {port} lookup main")
    for name in st["settings"].get("bypass_users", []):
        try:
            uid = pwd.getpwnam(name).pw_uid if not name.isdigit() else int(name)
        except KeyError:
            continue
        for fam in ("-4", "-6"):
            rules.append(f"{fam} rule %s priority 8990 uidrange {uid}-{uid} lookup main")
    add = "\n".join(f"ExecStartPre=-+/usr/bin/ip {r % 'add'}" for r in rules)
    units = st["settings"].get("before_units") or []
    # сервисы, которым нужен VPN (боты и т.п.), стартуют уже после туннеля
    before = f"Before={' '.join(units)}\n" if units else ""
    delete = "\n".join(f"ExecStopPost=-+/usr/bin/ip {r % 'del'}" for r in rules)
    return f"""# Сгенерировано sbx (~/scripts/sbx.py install). Правки затрёт следующий install.
[Unit]
Description=sbx — sing-box VPN client
Documentation=file://{Path(__file__).resolve()}
After=network-online.target nss-lookup.target
Wants=network-online.target
{before}RequiresMountsFor={CONF_DIR} {WORK_DIR}
# при загрузке не сдаваться после нескольких падений подряд
StartLimitIntervalSec=0

[Service]
User={user}
Group={user}
# TUN и маршруты без root: только нужные capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
# Ответы своих серверов (WireGuard, Caddy) уходят по main, мимо правил TUN (приоритет 9000+)
{add}
ExecStartPre={SING_BOX} check -c {CONFIG_FILE}
ExecStart={SING_BOX} run -c {CONFIG_FILE} -D {WORK_DIR}
ExecReload=/bin/kill -HUP $MAINPID
{delete}
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"""


def timer_units():
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or HOME.name
    exe = Path(sys.argv[0]).absolute() if axiom_mode() else Path(__file__).resolve()
    args = "sub update" if axiom_mode() else "update"
    env = {key: os.environ[key] for key in ("SBX_HOME", "SBX_AXIOM_HOME", "SBX_SING_BOX", "XDG_DATA_HOME")
           if os.environ.get(key)}
    if axiom_mode():
        env["SBX_BRAND"] = "axiom"

    def quote(value):
        return json.dumps(str(value).replace("%", "%%"), ensure_ascii=False)

    settings = "".join(f"Environment={quote(key + '=' + value)}\n" for key, value in env.items())
    svc = f"""[Unit]
Description=sbx — обновление подписок
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User={user}
{settings}ExecStart=/usr/bin/python3 {quote(exe)} {args} --quiet
"""
    tmr = """[Unit]
Description=sbx — обновление подписок по расписанию

[Timer]
OnBootSec=3min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
"""
    return svc, tmr


def sudo_write(path, text):
    run(sudo_cmd("tee", str(path)), input=text, stdout=subprocess.DEVNULL)


def install_units(st, quiet=False):
    if IS_WIN:
        return install_windows_tasks(st, quiet)
    svc, tmr = timer_units()
    files = {UNIT_DIR / UNIT: unit_text(st), UNIT_DIR / f"{UPDATE}.service": svc,
             UNIT_DIR / f"{UPDATE}.timer": tmr}
    changed = False
    for path, text in files.items():
        if not path.exists() or path.read_text() != text:
            sudo_write(path, text)
            changed = True
    if changed:
        systemctl("daemon-reload", sudo=True)
        if not quiet:
            print(f"✓ юниты установлены: {UNIT}, {UPDATE}.timer")
    if BASE == "axiom" and install_polkit_rule() and not quiet:
        print(f"✓ правило polkit: {POLKIT_RULE}")
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    return changed


def foreign_tun():
    """Другой VPN с TUN (Koala Clash / mihomo и т.п.) — маршруты подерутся."""
    if IS_WIN:
        return []
    r = run(["pgrep", "-a", "-f", "mihomo|clash-meta|xray|hiddify|nekobox|throne"],
            check=False, capture_output=True)
    return [l for l in r.stdout.splitlines() if "sbx" not in l and "pgrep" not in l]


TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def task_call(action, name=None, *args, check=True, capture=True):
    return run(["schtasks", f"/{action}", "/tn", name or BASE, *args], check=check, capture_output=capture)


TASK_STOPPED = {"ready", "disabled", "queued"}


def task_state(name=None):
    """Состояние задачи Планировщика: "running" | "stopped" | "unknown" (запрос не удался или ответ не разобран)."""
    name = name or BASE
    result = task_call("query", name, "/fo", "csv", "/nh", check=False)
    if result.returncode:
        return "unknown"
    row = next((r for r in csv.reader(result.stdout.splitlines()) if r), [])
    if row and row[-1].lower() == "running":
        return "running"
    if row and row[-1].lower() in TASK_STOPPED:
        return "stopped"
    # статус schtasks локализован — спрашиваем числовое состояние (1 Disabled, 2 Queued, 3 Ready, 4 Running)
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  f"[int](Get-ScheduledTask -TaskName '{name}' -TaskPath '\\').State"],
                 check=False, capture_output=True)
    value = result.stdout.strip() if result.returncode == 0 else ""
    return {"4": "running", "1": "stopped", "2": "stopped", "3": "stopped"}.get(value, "unknown")


def task_running(name=None):
    """Работает ли задача; «неизвестно» здесь — False, поэтому для удаления и защиты нужен task_state."""
    return task_state(name) == "running"


def task_listed(name):
    """Есть ли задача: False — её нет, OSError — Планировщик не ответил (это не «нет задачи»).

    Перечень берётся без /tn: запрос конкретной задачи не отличает «нет» от сбоя и не находит чужое имя.
    """
    result = run(["schtasks", "/query", "/fo", "csv", "/nh"], check=False, capture_output=True)
    if result.returncode:
        raise OSError(f"schtasks /query завершился с кодом {result.returncode}: "
                      f"{(result.stderr or result.stdout or '').strip()}")
    wanted = "\\" + name.lower()
    return any(row and row[0].lower() == wanted for row in csv.reader(result.stdout.splitlines()))


def task_definition(name):
    result = task_call("query", name, "/xml", check=False)
    return ET.fromstring(result.stdout) if not result.returncode else None


def task_enabled(name):
    root = task_definition(name)
    if root is None:
        return "disabled"
    namespace = {"t": TASK_NS}
    enabled = root.findtext("t:Settings/t:Enabled", "true", namespace)
    if name == BASE:
        boot = root.find("t:Triggers/t:BootTrigger", namespace)
        enabled = (boot.findtext("t:Enabled", "true", namespace)
                   if boot is not None and enabled == "true" else "false")
    return "enabled" if enabled == "true" else "disabled"


def task_xml(command, sid, *, boot=None, work=None, reader_sid=None):
    root = ET.Element("Task", xmlns=TASK_NS, version="1.2")

    def element(parent, name, value):
        ET.SubElement(parent, name).text = value

    if reader_sid is not None:
        if not re.fullmatch(r"S-1(?:-[0-9]+)+", reader_sid):
            raise ValueError("недопустимый SID пользователя Windows")
        registration = ET.SubElement(root, "RegistrationInfo")
        element(registration, "SecurityDescriptor", f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{reader_sid})")
    triggers = ET.SubElement(root, "Triggers")
    if boot is not None:
        element(ET.SubElement(triggers, "BootTrigger"), "Enabled", str(boot).lower())
    else:
        trigger = ET.SubElement(triggers, "TimeTrigger")
        element(trigger, "StartBoundary", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() + 180)))
        element(ET.SubElement(trigger, "Repetition"), "Interval", "PT6H")
    principal = ET.SubElement(ET.SubElement(root, "Principals"), "Principal", id="Author")
    element(principal, "UserId", sid)
    if boot is None:
        element(principal, "LogonType", "InteractiveToken")
    element(principal, "RunLevel", "HighestAvailable" if boot is not None else "LeastPrivilege")
    settings = ET.SubElement(root, "Settings")
    element(settings, "DisallowStartIfOnBatteries", "false")
    element(settings, "StopIfGoingOnBatteries", "false")
    element(settings, "ExecutionTimeLimit", "PT0S" if boot is not None else "PT30M")
    action = ET.SubElement(ET.SubElement(root, "Actions", Context="Author"), "Exec")
    element(action, "Command", command[0])
    element(action, "Arguments", subprocess.list2cmdline(command[1:]))
    if work is not None:
        element(action, "WorkingDirectory", str(work))
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def register_task(name, xml, *, system=False):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "task.xml"
        path.write_bytes(xml)
        user = ["/ru", "SYSTEM"] if system else []
        task_call("create", name, "/xml", str(path), *user, "/f", capture=False)


def protected_runtime():
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        program_files = Path(winreg.QueryValueEx(key, "ProgramFilesDir")[0])
    return program_files / ("AxiOm" if BASE == "axiom" else "SBX VPN") / ("cli-service" if BASE == "axiom" else "service")


def published_config(cfg, runtime):
    cfg["log"]["output"] = str(runtime / "sing-box.log")
    for ruleset in cfg["route"]["rule_set"]:
        tag = ruleset["tag"]
        if not re.fullmatch(r"(?:geosite|geoip)-[a-z0-9][a-z0-9!@._-]*", tag):
            raise ValueError("недопустимое имя rule-set для задачи SYSTEM")
        name = f"{tag}.srs"
        shutil.copyfile(RULESET_DIR / name, runtime / name)
        ruleset["path"] = str(runtime / name)
    return cfg


def check_system_outbound(options):
    if isinstance(options, dict):
        for key, value in options.items():
            if key != "path" or options.get("type") not in {"ws", "http", "httpupgrade"}:
                if (key == "path" or key.endswith(("_file", "_path", "_directory", "_provider"))) and value:
                    raise ValueError(f"параметр узла {key} с внешним файлом запрещён для задачи SYSTEM")
            check_system_outbound(value)
    elif isinstance(options, list):
        for value in options:
            check_system_outbound(value)


def publish_windows_config(st):
    runtime = protected_runtime()
    servers = all_servers(st)
    for server in servers:
        check_system_outbound(server["outbound"])
    cfg = published_config(build_config(st, servers), runtime)
    with tempfile.TemporaryDirectory(dir=runtime) as directory:
        candidate = Path(directory) / "config.json"
        write_private(candidate, json.dumps(cfg, ensure_ascii=False, indent=2))
        result = run([str(runtime / "sing-box.exe"), "check", "-c", str(candidate)],
                     check=False, capture_output=True, cwd=runtime)
        if result.returncode:
            die(f"sing-box отверг конфиг задачи SYSTEM:\n{result.stderr or result.stdout}")
        os.replace(candidate, runtime / "config.json")


def register_windows_service(boot):
    runtime = protected_runtime()
    command = [str(runtime / "sing-box.exe"), "run", "-c", str(runtime / "config.json"),
               "-D", str(runtime)]
    xml = task_xml(command, "S-1-5-18", boot=boot, work=runtime, reader_sid=windows_user_sid())
    register_task(BASE, xml, system=True)


def install_windows_tasks(st, quiet=False):
    settings = st["settings"]
    if not quiet and (settings["bypass_sports"] or settings["bypass_users"]):
        warn("Windows: bypass_sports и bypass_users не применяются")
    runtime = protected_runtime()
    if not runtime.exists():
        runtime.mkdir(parents=True)
        run(["icacls", str(runtime), "/inheritance:r", "/grant:r",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-3-4:(OI)(CI)RX",
             f"*{windows_user_sid()}:(OI)(CI)RX"],
            capture_output=True)
    # SYSTEM использует отдельное ядро и конфиг из защищённого каталога.
    if not (runtime / "sing-box.exe").exists():
        if override := os.environ.get("SBX_SING_BOX"):
            core = Path(override).resolve(strict=True)
            shutil.copyfile(core, runtime / "sing-box.exe")
            if (dll := core.with_name("libcronet.dll")).is_file():
                shutil.copyfile(dll, runtime / dll.name)
        else:
            install_core(runtime)
    publish_windows_config(st)
    if task_definition(BASE) is None:
        register_windows_service(False)
    update_windows_updater()


def windows_user_sid():
    rows = csv.reader(run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True).stdout.splitlines())
    return next(row for row in rows if row)[-1]


def updater_command():
    args = ["sub", "update", "-q"] if axiom_mode() else ["update", "-q"]
    # задача запускается без окружения установщика: пути, с которыми её зарегистрировали, пишем в командную строку
    return launch_command([*override_arguments(absolute=True), *args])


def register_windows_updater():
    register_task(UPDATE, task_xml(updater_command(), windows_user_sid()))


def registered_action(root):
    """-> (программа, аргументы) действия зарегистрированной задачи; пробелы по краям значения не важны."""
    namespace = {"t": TASK_NS}
    return tuple((root.findtext(f"t:Actions/t:Exec/t:{part}", "", namespace) or "").strip()
                 for part in ("Command", "Arguments"))


def update_windows_updater():
    """Задача обновления подписок: нет — создать; действие устарело (иные пути, программа) — перерегистрировать."""
    root = task_definition(UPDATE)
    if root is None:
        register_windows_updater()
        return
    command = updater_command()
    if registered_action(root) == (command[0].strip(), subprocess.list2cmdline(command[1:]).strip()):
        return
    was_disabled = task_enabled(UPDATE) == "disabled"
    register_windows_updater()
    if was_disabled:   # перерегистрация не должна включить то, что пользователь выключил (`sbx disable --timer`)
        task_call("change", UPDATE, "/disable", capture=False)


def prepare_service(st):
    if not all_servers(st):
        die("серверов нет: добавьте подписку (sbx sub add) или сервер (sbx add)")
    if st.get("_axiom") and effective_route(st) == "ru" and any(
            not (RULESET_DIR / f"{tag}.srs").exists() for tag in RULESETS):
        update_rulesets(st)
    if not IS_WIN:
        apply(st, reload=False)
    install_units(st)


POLKIT_RULE = Path("/etc/polkit-1/rules.d/50-axiom-cli.rules")


def polkit_rule_text(user):
    return ("// AxiOm CLI: allow the installing user to start/stop/restart axiom.service without a password\n"
            "polkit.addRule(function(action, subject) {\n"
            '    if (action.id == "org.freedesktop.systemd1.manage-units" &&\n'
            '        action.lookup("unit") == "' + UNIT + '" &&\n'
            '        ["start", "stop", "restart"].indexOf(action.lookup("verb")) >= 0 &&\n'
            '        subject.user == "' + user + '") {\n'
            "        return polkit.Result.YES;\n"
            "    }\n"
            "});\n")


def installing_user():
    import getpass
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
        raise ValueError(f"недопустимое имя пользователя для правила polkit: {user}")
    return user


def install_polkit_rule():
    """AxiOm: правило polkit, чтобы приложение и CLI без пароля запускали/останавливали axiom.service."""
    text = polkit_rule_text(installing_user())
    if not POLKIT_RULE.exists() or POLKIT_RULE.read_text() != text:
        run(sudo_cmd("mkdir", "-p", str(POLKIT_RULE.parent)))
        sudo_write(POLKIT_RULE, text)
        return True
    return False


def service_action(action):
    if not IS_WIN:
        if BASE == "axiom" and POLKIT_RULE.exists():
            if systemctl(action, UNIT, check=False, capture=True).returncode == 0:
                return      # правило polkit сработало без sudo
        systemctl(action, UNIT, sudo=True)
        return
    if action == "stop" or action == "restart" and task_running():
        task_call("end", capture=False)
        if action == "restart":
            for _ in range(25):
                if not task_running():
                    break
                time.sleep(0.2)
            else:
                die("задача sbx не остановилась")
    if action in {"start", "restart"}:
        task_call("run", capture=False)


# ─── команды ──────────────────────────────────────────────────────────────────

def retry_pending_fetch(st):
    """Ожидающее скачивание перенесённой подписки: повторяется при каждой команде, пока серверы не придут."""
    names = [name for name in st.get("pending_fetch", []) if any(sub["name"] == name for sub in st["subs"])]
    try:
        update_subs(st, names, quiet=True)
    except (OSError, ValueError, urllib.error.URLError):
        pass
    left = [name for name in names if not load_sub_cache(name)["servers"]]
    if left:
        warn("серверы перенесённой подписки не скачались (повторю при следующей команде): " + ", ".join(left))
        st["pending_fetch"] = left
    else:
        st.pop("pending_fetch", None)
    save_state(st)


def cmd_sub(st, a):
    app = st.get("_axiom")
    shared = app and app["root"]
    if a.action == "add":
        if shared:
            if a.ua or a.no_hwid:
                warn("профили приложения всегда используют User-Agent AxiOm, без HWID")
            name = write_axiom_profile(app, name=a.name, url=a.url)
            print(f"✓ {name}: добавлена")
            update_rulesets(st)
            apply(st)
            return
        if app:
            warn("база AxiOm не найдена; подписка будет локальной для sbx")
        sub_file(a.name)
        if any(s["name"] == a.name for s in st["subs"]):
            die(f"подписка {a.name} уже есть (sbx sub rm {a.name})")
        sub = {"name": a.name, "url": a.url, "hwid": not a.no_hwid}
        if a.ua:
            sub["ua"] = a.ua
        st["subs"].append(sub)
        save_state(st)
        if not update_subs(st, [a.name]):
            warn("подписка сохранена, но пока пустая — повторите `sbx update`")
            return
        apply(st)
    elif a.action == "rm":
        if shared and a.name.startswith("app:"):
            remove_app_profile(app, a.name[4:])
            if all_servers(st):
                apply(st)
            print(f"✓ подписка {a.name} удалена")
            return
        before = len(st["subs"])
        st["subs"] = [s for s in st["subs"] if s["name"] != a.name]
        if len(st["subs"]) == before:
            die(f"нет подписки {a.name}")
        sub_file(a.name).unlink(missing_ok=True)
        save_state(st)
        if all_servers(st):
            apply(st)
        print(f"✓ подписка {a.name} удалена")
    else:
        profiles = app["profiles"] if app else []
        if not st["subs"] and not profiles:
            print("подписок нет: sbx sub add ИМЯ URL")
        for row in profiles:
            servers, _ = app_cache(app, row)
            metadata = {key: row.get(key) or 0 for key in ("upload", "download", "total")}
            cache = read_app_cache(app, row) if row["id"] not in owned_profile_ids() else None
            metadata.update(updated=cache["refreshed"] if cache else epoch_date(row.get("last_update")),
                            expire=epoch_date(row.get("expire")))
            name = app_sub_name(row) + (" (активна)" if row.get("active") else "")
            show_subscription(name, len(servers), metadata, row.get("url") if a.verbose else None)
        for s in st["subs"]:
            c = load_sub_cache(s["name"])
            show_subscription(s["name"], len(c["servers"]), c["meta"],
                              (s.get("url") or s.get("local_path")) if a.verbose else None)


def show_subscription(name, count, meta, location):
    line = f"{name}: {count} серверов"
    if meta.get("title"):
        line += f" · {meta['title']}"
    if meta.get("updated"):
        line += f" · обновлена {time.strftime('%d.%m %H:%M', time.localtime(meta['updated']))}"
    print(line)
    used = meta.get("upload", 0) + meta.get("download", 0)
    if meta.get("total"):
        print(f"    трафик {human_bytes(used)} из {human_bytes(meta['total'])}")
    elif used:
        print(f"    трафик {human_bytes(used)}")
    if meta.get("expire"):
        days = (meta["expire"] - time.time()) / 86400
        print(f"    до {time.strftime('%d.%m.%Y', time.localtime(meta['expire']))} (осталось {days:.0f} дн.)")
    if location:
        print(f"    {location}")


def cmd_update(st, a):
    ok = update_subs(st, a.names or None, quiet=a.quiet)
    save_state(st)
    if all_servers(st):
        apply(st, quiet=a.quiet)
    if not ok:
        sys.exit(1)


def cmd_add(st, a):
    added = 0
    for uri in a.uris:
        try:
            name, o = parse_uri(uri)
        except (Unsupported, KeyError, ValueError, json.JSONDecodeError) as e:
            warn(f"не добавлен: {e}")
            continue
        name = a.name if a.name and len(a.uris) == 1 else (name or f"{o['type']} {o['server']}")
        st["manual"].append({"name": name, "outbound": o})
        print(f"✓ {name} ({o['type']} {o['server']}:{o['server_port']})")
        added += 1
    if added:
        save_state(st)
        apply(st)


def cmd_rm(st, a):
    server = resolve_server(st, a.server, allow_auto=False)
    index = server.get("manual_index")
    if index is None:
        die(f"{server['tag']} пришёл из подписки — удаляется только вместе с ней (или auto_exclude)")
    # выбор хранится тегом, а теги одноимённых ручных серверов сдвигаются при удалении: следим по записи
    servers = all_servers(st)
    chosen = next((s for s in servers if s["tag"] == st["selected"]), None)
    extra = st["axiom_extra"] if isinstance(st.get("axiom_extra"), dict) else None
    extra_record = next((s for s in servers if extra and s["tag"] == extra.get("tag")), None)
    del st["manual"][index]   # именно запись под этим номером, а не однофамилец по имени
    after = {s["manual_index"]: s["tag"] for s in all_servers(st) if "manual_index" in s}

    def new_tag(record):
        """Тег записи после удаления: None — не менялся, "" — запись удалена."""
        i = record.get("manual_index")
        if i is None:
            return None
        return "" if i == index else after[i - (i > index)]

    if chosen is not None and (tag := new_tag(chosen)) is not None:
        st["selected"] = tag or "auto"
    if extra_record is not None and (tag := new_tag(extra_record)) is not None:
        if tag:
            extra["tag"] = tag
        else:
            st.pop("axiom_extra")
    save_state(st)
    apply(st)
    print(f"✓ удалён {server['tag']}")


def resolve_server(st, query, allow_auto=True, hidden_exact=False):
    """Номер, имя или часть имени -> запись сервера из all_servers (или "auto").

    Номера — как в `ls` (меню AxiOm, потом свои). hidden_exact: точное имя ищется и среди серверов,
    скрытых из меню (исходящие приложения AxiOm), — нужно правилам via.
    """
    if allow_auto and query.lower() in {"auto", "0"}:
        return "auto"
    everything = all_servers(st)
    servers = numbered_servers(st, everything)
    if query.isdigit():
        i = int(query)
        if 1 <= i <= len(servers):
            return servers[i - 1]
        die(f"номера {i} нет, всего {len(servers)}")
    exact = [s for s in (everything if hidden_exact else servers) if s["tag"] == query]
    if exact:
        return exact[0]
    found = [s for s in servers if query.lower() in s["tag"].lower()]
    if len(found) == 1:
        return found[0]
    if not found:
        die(f"не найден сервер «{query}» (sbx ls)")
    die("под «%s» подходят несколько:\n  %s" % (query, "\n  ".join(s["tag"] for s in found)))


def resolve(st, query, allow_auto=True, hidden_exact=False):
    server = resolve_server(st, query, allow_auto, hidden_exact)
    return server if server == "auto" else server["tag"]


def cmd_ls(st, a):
    servers = all_servers(st)
    if not servers:
        print("серверов нет: sbx sub add ИМЯ URL")
        return
    if st.get("_axiom") and (menu := axiom_menu(servers))[0]:
        ls_axiom(st, servers, menu, a.filter)
        return
    now = current_node(st) if is_active(st) else None
    live = now.split(" → ")[-1] if now else None
    sel = st["selected"]
    print(f"{'●' if sel == 'auto' else ' '}   0  auto" + (f"  → {live}" if sel == "auto" and live else ""))
    rx = st["settings"].get("auto_exclude")
    for i, s in enumerate(servers, 1):
        if a.filter and a.filter.lower() not in s["tag"].lower():
            continue
        mark = "●" if s["tag"] == sel else ("›" if sel == "auto" and s["tag"] == live else " ")
        ms = st["latency"].get(s["tag"])
        lat = "" if ms is None else ("  —" if ms < 0 else f"{ms:>5} мс")
        o = s["outbound"]
        kind = o["type"] + ("+reality" if (o.get("tls") or {}).get("reality") else "")
        noauto = "  (не в auto)" if rx and re.search(rx, s["tag"], re.I) else ""
        print(f"{mark} {i:>3}  {s['tag']:<34} {kind:<16}{lat:>9}  [{s['source']}]{noauto}")


def cmd_use(st, a):
    triple = None
    if getattr(a, "select", None):
        triple, tag = resolve_select(st, a.select)
    else:
        tag = resolve(st, a.server)
    app = st.get("_axiom")
    sync = sync_dir() if app and app.get("root") else None
    app_running = bool(sync and app_state(sync))     # свежее сердцебиение: файл настроек пишет только приложение
    send = False
    if app:
        options, extras = axiom_menu(all_servers(st))
        choice = next((key for key, node in options if node == tag), None)
        if tag == "auto" or choice:
            triple = triple or (tuple(choice) if choice else (AXIOM_AUTO, "", ""))
            if app_running:
                send = True
                remember_selection(app, triple)
            else:
                axiom_write_selection(app, choice)
            st.pop("axiom_extra", None)
        elif options and tag in extras:
            st["axiom_extra"] = {"tag": tag, "prefs": axiom_prefs_now(app)}
            if app_running:
                warn("свой сервер sbx нельзя применить в приложении AxiOm: выбор сохранён только для CLI")
    st["selected"] = tag
    save_state(st)
    if send:
        send_app_command(sync, "select", triple)      # раньше конфига CLI: приложению не нужны ни ядро, ни apply
    try:
        apply(st, reload=False)
    except (SystemExit, Exception) as e:
        if not send:
            raise
        code = e.code if isinstance(e, SystemExit) else e
        print(f"ℹ выбор принят приложением AxiOm; конфиг CLI не обновлён ({code})")
        print(f"✓ выбран {tag}")
        return
    if is_active(st) and api_up(st):
        api(st, "PUT", "/proxies/proxy", {"name": tag})

    if IS_WIN and interactive() and task_definition(BASE) is not None:
        warn("для сохранения выбора после перезагрузки задачи SYSTEM: sbx restart")
    print(f"✓ выбран {tag}")


def cmd_use_or_pick(st, a):
    if a.select and a.server:
        die("укажите либо сервер, либо --select")
    if a.server or a.select:
        cmd_use(st, a)
    else:
        cmd_pick(st, a)


def ls_axiom(st, servers, menu, query):
    ordered, all_extras = menu
    options = ordered
    latencies = dict(st["latency"])
    if is_active(st):
        try:
            proxies = api(st, "GET", "/proxies")["proxies"]
            for _, tag in options:
                history = proxies.get(tag, {}).get("history", [])
                if history:
                    latencies[tag] = history[-1]["delay"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    selected = selected_server(st, servers)
    best = axiom_fastest(options, latencies)
    print(f"{'●' if selected == 'auto' else ' '}   0  Авто (самый быстрый)" + (f" → {best}" if best else ""))
    previous = ()
    for index, (key, tag) in enumerate(ordered, 1):
        if query and query.lower() not in tag.lower():
            continue
        country, protocol, transport = key
        if previous[:1] != key[:1]:
            print(f"{axiom_flag(country)} {country}")
        if previous[:2] != key[:2]:
            print(f"     {AXIOM_PROTOCOLS[protocol]}")
        previous = key
        mark = "●" if selected == tag else "›" if selected == "auto" and best == tag else " "
        delay = latencies.get(tag, 0)
        detail = f" · {delay} мс" if isinstance(delay, int) and 0 < delay < 65000 else ""
        print(f"{mark}   {index:>2}  {AXIOM_TRANSPORTS[transport]}{detail}")
    extras = [tag for tag in all_extras if not query or query.lower() in tag.lower()]
    if extras:
        print("Свои серверы")
        by_tag = {server["tag"]: server for server in servers}
        for tag in extras:
            index = len(ordered) + all_extras.index(tag) + 1
            delay = latencies.get(tag, 0)
            detail = f" · {delay} мс" if isinstance(delay, int) and 0 < delay < 65000 else ""
            print(f"{'●' if selected == tag else ' '}   {index:>2}  {tag}  [{by_tag[tag]['source']}]{detail}")


class Prober:
    """Замер задержки через clash API: работающего sbx или временного sing-box без TUN.

    Временный поднимается лениво, на первом замере: прав не нужно, мешать работающему нечему.
    """

    def __init__(self, st, timeout=5.0):
        self.st, self.timeout = st, timeout
        self.port, self.proc, self.tmpdir = None, None, None
        self.url = urllib.parse.quote(st["settings"]["test_url"], safe="")

    def ensure(self):
        if self.port:
            return
        if is_active(self.st) and api_up(self.st):
            self.port = self.st["settings"]["api_port"]
            return
        self.tmpdir = Path(tempfile.mkdtemp(prefix="sbx-test-"))
        port = free_port()
        cfg = build_config(self.st, all_servers(self.st), tun=False, api_port=port,
                           mixed_port=free_port())
        if IS_WIN:
            cfg["log"]["output"] = str(self.tmpdir / "sing-box.log")
        (self.tmpdir / "c.json").write_text(json.dumps(cfg), encoding="utf-8")
        self.proc = subprocess.Popen(
            [core_path(), "run", "-c", str(self.tmpdir / "c.json"), "-D", str(self.tmpdir)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if api_up(self.st, port):
                self.port = port
                return
            time.sleep(0.1)
        self.close()
        raise RuntimeError("временный sing-box не поднялся")

    def delay(self, tag):
        """-> мс или -1."""
        path = (f"/proxies/{urllib.parse.quote(tag, safe='')}/delay"
                f"?url={self.url}&timeout={int(self.timeout * 1000)}")
        try:
            return api(self.st, "GET", path, port=self.port, timeout=self.timeout + 3)["delay"]
        except (urllib.error.URLError, OSError, KeyError, ValueError):
            return -1

    def close(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None
        self.port = None


def cmd_test(st, a):
    servers = numbered_servers(st, all_servers(st))
    indices = {s["tag"]: i for i, s in enumerate(servers, 1)}
    if a.filter:
        servers = [s for s in servers if a.filter.lower() in s["tag"].lower()]
    if not servers:
        die("нечего проверять")
    prober = Prober(st, a.timeout)
    try:
        prober.ensure()
        with ThreadPoolExecutor(8) as ex:
            results = dict(zip((s["tag"] for s in servers),
                               ex.map(prober.delay, (s["tag"] for s in servers))))
            # первая волна на холодную (DNS, TLS) даёт ложные отказы — упавшим второй шанс
            retry = [t for t, ms in results.items() if ms < 0]
            results.update(zip(retry, ex.map(prober.delay, retry)))
    except RuntimeError as e:
        die(str(e))
    finally:
        prober.close()
    st["latency"].update(results)
    save_state(st)
    for tag, ms in sorted(results.items(), key=lambda r: (r[1] < 0, r[1])):
        print(f"{indices[tag]:>4}  {tag:<34} {'недоступен' if ms < 0 else f'{ms} мс':>10}")


def disp_width(text):
    """Ширина в ячейках терминала: эмодзи и CJK занимают две."""
    import unicodedata
    w = 0
    for ch in text:
        if unicodedata.combining(ch) or ch in "\u200d\ufe0f":
            continue
        w += 2 if unicodedata.east_asian_width(ch) in "WF" else 1
    return w


def fit(text, width):
    """Обрезать/дополнить до ровно width ячеек."""
    out, w = "", 0
    for ch in text:
        cw = disp_width(ch)
        if w + cw > width:
            break
        out, w = out + ch, w + cw
    return out + " " * (width - w)


def numbered_choice(options):
    try:
        answer = input("Номер (Enter — отмена): ").strip()
    except EOFError:
        return None
    if not answer:
        return None
    if not answer.isdecimal() or int(answer) not in options:
        die("нет такого номера")
    return options[int(answer)]


OWN_SERVERS = "\0own"


def pick_axiom(options, extras=()):
    options = axiom_sorted(options)
    countries = list(dict.fromkeys(key[0] for key, _ in options))
    print("  0  Авто (самый быстрый)")
    print("Страна:")
    for index, country in enumerate(countries, 1):
        print(f"{index:>3}  {axiom_flag(country)} {country}")
    choices = {0: AXIOM_AUTO, **dict(enumerate(countries, 1))}
    if extras:
        choices[len(countries) + 1] = OWN_SERVERS
        print(f"{len(countries) + 1:>3}  Свои серверы")
    country = numbered_choice(choices)
    if country is None:
        return None
    if country == AXIOM_AUTO:
        return "auto"
    if country == OWN_SERVERS:
        for index, tag in enumerate(extras, 1):
            print(f"{index:>3}  {tag}")
        return numbered_choice(dict(enumerate(extras, 1)))
    options = [(key, tag) for key, tag in options if key[0] == country]
    protocols = list(dict.fromkeys(key[1] for key, _ in options))
    if len(protocols) > 1:
        print("Протокол:")
        for index, protocol in enumerate(protocols, 1):
            print(f"{index:>3}  {AXIOM_PROTOCOLS[protocol]}")
        protocol = numbered_choice(dict(enumerate(protocols, 1)))
        if protocol is None:
            return None
    else:
        protocol = protocols[0]
    transports = [(key[2], tag) for key, tag in options if key[1] == protocol]
    if len(transports) == 1:
        return transports[0][1]
    print("Транспорт:")
    for index, (transport, _) in enumerate(transports, 1):
        print(f"{index:>3}  {AXIOM_TRANSPORTS[transport]}")
    return numbered_choice({index: tag for index, (_, tag) in enumerate(transports, 1)})


def cmd_pick(st, a):
    """Интерактивный выбор: ↑↓ листать, пробел — пинг, a — пинг всех, Enter — выбрать."""
    try:
        import curses
    except ImportError:
        curses = None
    import threading
    if not interactive():
        die("нужен терминал; без него: sbx use НОМЕР|ИМЯ|auto")
    servers = all_servers(st)
    if not servers:
        die("серверов нет: sbx sub add ИМЯ URL")
    if st.get("_axiom"):
        options, extras = axiom_menu(servers)
        if options:
            choice = pick_axiom(options, extras)
            if choice is not None:
                cmd_use(st, argparse.Namespace(server=choice))
            return choice
    if curses is None or not interactive() or not os.environ.get("TERM") and not IS_WIN:
        options = {0: "auto", **{index: server["tag"] for index, server in enumerate(servers, 1)}}
        for index, tag in options.items():
            print(f"{index:>4}  {tag}")
        choice = numbered_choice(options)
        if choice is not None:
            cmd_use(st, argparse.Namespace(server=choice))
        return choice
    items = [{"tag": "auto", "kind": "urltest", "source": ""}] + [
        {"tag": s["tag"], "source": s["source"],
         "kind": s["outbound"]["type"] + ("+reality" if (s["outbound"].get("tls") or {}).get("reality") else "")}
        for s in servers]
    rx = st["settings"].get("auto_exclude")
    running = is_active(st) and api_up(st)
    live = (current_node(st) or "").split(" → ")[-1] if running else None
    lat = dict(st["latency"])
    pending = set()
    status = {"msg": ""}
    prober = Prober(st)
    pool = ThreadPoolExecutor(8)
    lock = threading.Lock()

    def ping(tags):
        def job(tag):
            try:
                with lock:
                    prober.ensure()
            except RuntimeError as e:
                status["msg"] = str(e)
                pending.discard(tag)
                return
            ms = prober.delay(tag)
            lat[tag] = ms
            pending.discard(tag)
        for tag in tags:
            if tag not in pending:
                pending.add(tag)
                pool.submit(job, tag)

    def ui(scr):
        curses.curs_set(0)
        scr.timeout(150)
        scr.keypad(True)
        curses.use_default_colors()
        for i, c in enumerate((curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED,
                               curses.COLOR_CYAN), 1):
            curses.init_pair(i, c, -1)
        sel = st["selected"] if st["selected"] in [it["tag"] for it in items] else "auto"
        cur = next(i for i, it in enumerate(items) if it["tag"] == sel)
        top = 0
        while True:
            h, w = scr.getmaxyx()
            rows = max(1, h - 3)
            cur = max(0, min(cur, len(items) - 1))
            top = min(max(top, cur - rows + 1), cur)
            scr.erase()
            head = "Сервер VPN   ↑↓ PgUp PgDn — листать · пробел — пинг · a — все · Enter — выбрать · q — выход"
            scr.addstr(0, 0, fit(head, w - 1), curses.A_BOLD)
            name_w = max(10, min(40, w - 40))
            for row, it in enumerate(items[top:top + rows]):
                i = top + row
                tag = it["tag"]
                mark = "●" if tag == sel else ("›" if sel == "auto" and tag == live else " ")
                num = "  0" if i == 0 else f"{i:>3}"
                if tag in pending:
                    lat_s, color = "   …   ", 4
                elif tag in lat:
                    ms = lat[tag]
                    lat_s = " —  " if ms < 0 else f"{ms:>4} мс"
                    color = 3 if ms < 0 else (1 if ms < 150 else 2 if ms < 400 else 3)
                else:
                    lat_s, color = "", 0
                note = "  (не в auto)" if i and rx and re.search(rx, tag, re.I) else ""
                line = f" {mark} {num}  {fit(tag, name_w)} {fit(it['kind'], 15)}"
                attr = curses.A_REVERSE if i == cur else curses.A_NORMAL
                try:
                    scr.addstr(row + 1, 0, fit(line, w - 1), attr)
                    x = disp_width(line) + 1
                    if lat_s and x + 8 < w:
                        scr.addstr(row + 1, x, fit(lat_s, 8), attr | curses.color_pair(color))
                    if note and x + 9 + len(note) < w:
                        scr.addstr(row + 1, x + 8, note, attr | curses.A_DIM)
                except curses.error:
                    pass
            state = "работает" if running else "выключен — пинг через временный sing-box"
            foot = f" VPN {state} · выбран: {sel}"
            if pending:
                foot += f" · проверяю {len(pending)}…"
            if status["msg"]:
                foot += f" · {status['msg']}"
            try:
                scr.addstr(h - 1, 0, fit(foot, w - 1), curses.A_DIM)
            except curses.error:
                pass
            scr.refresh()

            k = scr.getch()
            if k in (curses.KEY_UP, ord("k")):
                cur -= 1
            elif k in (curses.KEY_DOWN, ord("j")):
                cur += 1
            elif k == curses.KEY_PPAGE:
                cur -= rows
            elif k == curses.KEY_NPAGE:
                cur += rows
            elif k == curses.KEY_HOME:
                cur = 0
            elif k == curses.KEY_END:
                cur = len(items) - 1
            elif k == ord(" "):
                ping([items[cur]["tag"]])
            elif k in (ord("a"), ord("A"), ord("ф"), ord("Ф")):
                ping([it["tag"] for it in items[1:]])
            elif k in (curses.KEY_ENTER, 10, 13):
                return items[cur]["tag"]
            elif k in (ord("q"), ord("Q"), ord("й"), ord("Й"), 27):
                return None

    os.environ.setdefault("ESCDELAY", "25")
    try:
        choice = curses.wrapper(ui)
    except KeyboardInterrupt:
        choice = None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        prober.close()
    st["latency"].update({t: ms for t, ms in lat.items() if t != "auto"})
    save_state(st)
    if choice is None:
        print("выбор не изменён")
        return
    cmd_use(st, argparse.Namespace(server=choice))
    return choice


def ip_snapshot():
    """Правила и маршруты всех таблиц — чтобы доказать, что проба ничего не перехватила."""
    lines = []
    for cmd in (["ip", "rule"], ["ip", "-6", "rule"], ["ip", "route", "show", "table", "all"]):
        lines += run(cmd, check=False, capture_output=True).stdout.splitlines()
    return {l.strip() for l in lines if PROBE_IF not in l}


def cmd_probe(st, a):
    """Проверка ядра, TUN и подписки рядом с работающим VPN (Koala и т.п.), без перехвата."""
    if is_active(st):
        die("sbx уже работает — проба не нужна, см. sbx status")
    if IS_WIN:
        print("Windows: проба проверяет ядро и серверы через временный mixed-прокси, без TUN.")
        cmd_test(st, argparse.Namespace(filter=None if a.all or st["selected"] == "auto"
                                        else st["selected"], timeout=5))
        return
    servers = all_servers(st)
    if not servers:
        die("серверов нет: sbx sub add ИМЯ URL")
    api_port, mixed = free_port(), free_port()
    cfg = build_config(st, servers, probe=True, api_port=api_port, mixed_port=mixed)
    probe_dir = WORK_DIR / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = probe_dir / "config.json"
    write_private(cfg_path, json.dumps(cfg, ensure_ascii=False))
    ok, err = check_config(cfg_path)
    if not ok:
        die(f"sing-box отверг конфиг:\n{err}")

    before = ip_snapshot()
    user = os.environ.get("USER") or HOME.name
    caps = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE"
    run(sudo_cmd("systemctl", "reset-failed", PROBE_UNIT), check=False, capture_output=True)
    run(sudo_cmd("systemd-run", f"--unit={PROBE_UNIT}", f"--uid={user}", f"--gid={user}",
                 "-p", f"AmbientCapabilities={caps}", "-p", f"CapabilityBoundingSet={caps}",
                 "--quiet", "--collect", SING_BOX, "run", "-c", str(cfg_path), "-D", str(probe_dir)))
    results = []

    def step(name, good, detail=""):
        results.append(good)
        print(f"{'✓' if good else '✗'} {name}" + (f": {detail}" if detail else ""))

    try:
        for _ in range(50):
            if api_up(st, api_port):
                break
            time.sleep(0.1)
        try:
            ver = api(st, "GET", "/version", port=api_port)["version"]
            step("ядро sing-box запущено", True, ver)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            step("ядро sing-box запущено", False, str(e))
            run(["journalctl", "-u", PROBE_UNIT, "-n", "20", "--no-pager", "-o", "cat"], check=False)
            return

        link = run(["ip", "-br", "link", "show", PROBE_IF], check=False, capture_output=True).stdout
        step(f"TUN {PROBE_IF} создан", bool(link.strip()), " ".join(link.split()[1:2]))

        url = urllib.parse.quote(st["settings"]["test_url"], safe="")
        targets = servers if a.all else [s for s in servers if s["tag"] == st["selected"]] or \
            [{"tag": "auto"}]
        for s in targets:
            path = f"/proxies/{urllib.parse.quote(s['tag'], safe='')}/delay?url={url}&timeout=5000"
            try:
                ms = api(st, "GET", path, port=api_port, timeout=8)["delay"]
                step(f"сервер {s['tag']}", True, f"{ms} мс")
            except (urllib.error.URLError, OSError, KeyError, ValueError):
                step(f"сервер {s['tag']}", False, "не отвечает")
        if not a.all:
            now = api(st, "GET", "/proxies/auto", port=api_port).get("now")
            if now:
                print(f"  auto выбрал: {now}")

        def curl(extra):
            r = run(["curl", "-sS", "-m", "15", *extra, "https://ipinfo.io/json"],
                    check=False, capture_output=True)
            try:
                j = json.loads(r.stdout)
                return True, f"{j.get('ip')} {j.get('country', '')} {j.get('org', '')}"
            except ValueError:
                return False, (r.stderr or r.stdout).strip()[:200]

        step("трафик через mixed-прокси", *curl(["-x", f"socks5h://127.0.0.1:{mixed}"]))
        # сокет, привязанный к интерфейсу, уходит в TUN и без маршрутов — только этот curl
        step("трафик через TUN", *curl(["--interface", PROBE_IF]))

        after = ip_snapshot()
        diff = (after - before) | (before - after)
        step("маршруты и ip rule не тронуты", not diff, "; ".join(sorted(diff))[:300])
    finally:
        run(sudo_cmd("systemctl", "stop", PROBE_UNIT), check=False, capture_output=True)
        gone = not run(["ip", "link", "show", PROBE_IF], check=False, capture_output=True).stdout
        print(f"{'✓' if gone else '✗'} проба остановлена, {PROBE_IF} {'удалён' if gone else 'остался!'}")
    if not all(results):
        sys.exit(1)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


RUN_CONFIG = re.compile(r'(?:^|\s)-c\s+(?:"([^"]+)"|(\S+))')


def run_config_path(command):
    """Путь конфига из командной строки `… run -c ПУТЬ …` (ExecStart юнита, Arguments задачи) или None."""
    match = RUN_CONFIG.search(command or "")
    return Path(match[1] or match[2]) if match else None


def listeners_of(config):
    """Конфиг sing-box -> (есть ли TUN, {роль настройки: порт}); роли — имена настроек sbx: mixed_port, api_port."""
    inbounds = [i for i in config.get("inbounds", []) if isinstance(i, dict)]
    tun = any(i.get("type") == "tun" for i in inbounds)
    ports = {}
    for inbound in inbounds:
        if inbound.get("type") in {"mixed", "socks", "http"} and isinstance(inbound.get("listen_port"), int):
            ports.setdefault("mixed_port", inbound["listen_port"])
    controller = ((config.get("experimental") or {}).get("clash_api") or {}).get("external_controller")
    if isinstance(controller, str) and controller.rpartition(":")[2].isdigit():
        ports["api_port"] = int(controller.rpartition(":")[2])
    return tun, ports


def installed_runtime_command(unit_name, task_name):
    """Командная строка, которую служба/задача сейчас реально запускает (из установленного юнита или задачи)."""
    if IS_WIN:
        root = task_definition(task_name)
        if root is None:
            return None
        namespace = {"t": TASK_NS}
        return root.findtext("t:Actions/t:Exec/t:Arguments", None, namespace)
    for line in (UNIT_DIR / unit_name).read_text(encoding="utf-8").splitlines():
        if line.startswith("ExecStart="):
            return line.partition("=")[2]
    return None


def other_brand_active():
    """Другая марка (sbx <-> AxiOm), если её служба/задача работает или это не удалось выяснить, иначе None.

    -> {"name", "tun": True|False|None, "listeners": {настройка: порт}}; tun None — установленный
    конфиг не прочитался (считаем конфликтом).
    """
    other_axiom = BASE != "axiom"
    names = identity_names(other_axiom)
    if IS_WIN:
        try:
            state = task_state(names["base"]) if task_listed(names["base"]) else "stopped"
        except OSError:
            state = "unknown"
        active = state != "stopped"
    else:
        r = systemctl("show", "-p", "ActiveState", "--value", names["unit"], check=False, capture=True)
        if getattr(r, "returncode", 0):
            active = True
        else:
            active = r.stdout.strip() in {"active", "activating", "reloading"}
    if not active:
        return None
    tun, listeners = None, {}
    try:
        path = run_config_path(installed_runtime_command(names["unit"], names["base"]))
        if path is not None:
            tun, listeners = listeners_of(json.loads(path.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError):
        tun, listeners = None, {}
    return {"name": names["base"], "tun": tun, "listeners": listeners}


def brand_conflict(st, other):
    """Почему эту марку нельзя запускать рядом с работающей другой (строка), либо None."""
    name = other["name"]
    if other["tun"] is None:
        return (f"работает {name}, но его установленный конфиг не прочитан — режим и порты неизвестны; "
                f"считаем это конфликтом")
    settings = st["settings"]
    if other["tun"] or settings["mode"] == "tun":
        return (f"работает {name} ({'TUN' if other['tun'] else 'прокси'}): "
                f"{BASE} и {name} используют те же адреса и маршруты TUN")
    for key in ("mixed_port", "api_port"):
        for their_key, port in other["listeners"].items():
            if settings[key] == port:
                return (f"порт {port} занят: {BASE} {key} = {port} совпадает с {name} {their_key} = {port}; "
                        f"смените его (`{BASE} set {key} N`)")
    return None


def refuse_other_brand(st, force):
    """Обе марки (sbx и AxiOm) вместе не включаем: TUN делят адреса и маршруты, а прокси — порты; обход — --force."""
    other = other_brand_active()
    if other and not force and (reason := brand_conflict(st, other)):
        die(f"{reason}.\nСначала выключите его ({other['name']} down) или запустите с --force")


APP_ON_MESSAGE = "VPN уже включён в приложении AxiOm"
APP_STARTING_MESSAGE = "VPN запускается другой стороной (приложение AxiOm) — свой движок не запускаю"


def cmd_up(st, a):
    sync = sync_dir()
    if sync and app_vpn_on(sync):
        print(APP_ON_MESSAGE)
        return
    if BASE == "axiom" and is_active(st):
        print("VPN уже включён (CLI); выбор, если он был, применён без перезапуска")
        return
    refuse_other_brand(st, a.force)
    if not require_windows_admin(["up", *(["--force"] if a.force else [])]):
        return
    others = foreign_tun()
    if others and not a.force:
        die("работает другой VPN-клиент, маршруты подерутся:\n  " + "\n  ".join(others) +
            "\nзакройте его или запустите с --force")
    with start_reservation(sync) as reserved:
        if not reserved:
            print(APP_STARTING_MESSAGE)
            return
        prepare_service(st)
        service_action("restart" if (task_running() if IS_WIN else is_active(st)) else "start")
        time.sleep(1.5)
        if IS_WIN:
            for _ in range(20):
                if is_active(st):
                    break
                time.sleep(0.25)
        if not is_active(st):
            cmd_log(st, argparse.Namespace(lines=30, follow=False, replace=False))
            die("sing-box не запустился")
    print("✓ VPN включён")
    show_status(st)


def cmd_down(st, a):
    sync = sync_dir()
    if sync:
        wait_app_start_finished(sync)         # приложение как раз запускается — дать ему закончить, потом выключить
    app_on = app_vpn_on(sync) if sync else None
    if app_on and not is_active(st):
        send_app_command(sync, "disconnect")     # своего движка нет — права и служба не нужны
        print("✓ VPN выключен (в приложении AxiOm)")
        return
    if not require_windows_admin(["down"]):
        return
    service_action("stop")
    if app_on:
        send_app_command(sync, "disconnect")
    print("✓ VPN выключен")


def cmd_restart(st, a):
    force = getattr(a, "force", False)
    refuse_other_brand(st, force)   # restart запускает и остановленную службу
    if not require_windows_admin(["restart", *(["--force"] if force else [])]):
        return
    prepare_service(st)
    service_action("restart")
    print("✓ перезапущен")


def show_status(st):
    active = is_active(st)
    enabled = task_enabled(BASE) if IS_WIN else unit_prop("UnitFileState")
    s = st["settings"]
    app_on = app_vpn_on()
    print(f"состояние:   {'работает' if active else 'выключен'}"
          f"  (автозапуск: {'да' if enabled == 'enabled' else 'нет'})")
    if app_on:
        print("приложение:  подключено через приложение AxiOm" + (f" · {app_on['rawTag']}" if app_on.get("rawTag") else ""))
    print(f"режим:       {'TUN + ' if s['mode'] == 'tun' else ''}прокси 127.0.0.1:{s['mixed_port']}"
          f" · маршрут {effective_route(st)}")
    selected = selected_server(st, all_servers(st)) if st.get("_axiom") else st["selected"]
    print(f"выбран:      {selected}")
    if active:
        node = current_node(st)
        if node:
            print(f"сейчас:      {node}")
    for v in s.get("via_rules", []):
        print(f"раздельно:   {', '.join(v['items'])} → {via_label(st, v['to'])}")
    if active:
        try:
            conns = api(st, "GET", "/connections")
            print(f"трафик:      ↑ {human_bytes(conns.get('uploadTotal', 0))}"
                  f"  ↓ {human_bytes(conns.get('downloadTotal', 0))}"
                  f"  · соединений {len(conns.get('connections') or [])}")
        except (urllib.error.URLError, OSError, ValueError):
            pass
    t = task_enabled(UPDATE) if IS_WIN else unit_prop_of(f"{UPDATE}.timer", "UnitFileState")
    manual = "вручную (axiom sub update)" if st.get("_axiom") else "вручную (sbx update)"
    print(f"обновление:  {'по таймеру раз в 6 ч' if t == 'enabled' else manual}")


def unit_prop_of(unit, prop):
    r = systemctl("show", "-p", prop, "--value", unit, check=False, capture=True)
    return r.stdout.strip()


def status_info(st):
    sync = sync_dir()
    app_on = app_vpn_on(sync) if sync else None
    cli_on = is_active(st)
    selection = None
    if app_on and isinstance(app_on.get("selection"), dict) and app_on["selection"].get("c"):
        chosen = app_on["selection"]
        selection = {key: chosen.get(key) or "" for key in "cpt"}
    elif st.get("_axiom") and st["_axiom"].get("root"):
        country, protocol, transport = (value or "" for value in axiom_prefs_now(st["_axiom"]))
        selection = {"c": country or AXIOM_AUTO, "p": protocol, "t": transport}
    server = None
    if cli_on:
        node = current_node(st)
        server = node.split(" → ")[-1] if node else None
    elif app_on:
        server = app_on.get("rawTag")
    return {"vpn": "on" if cli_on or app_on else "off", "engine": "cli" if cli_on else "app" if app_on else None,
            "selection": selection, "server": server, "version": __version__}


def cmd_status(st, a):
    if getattr(a, "json", False):
        print(json.dumps(status_info(st), ensure_ascii=False))
        return
    show_status(st)


def cmd_ip(st, a):
    proxy = urllib.request.ProxyHandler({p: f"http://127.0.0.1:{st['settings']['mixed_port']}"
                                         for p in ("http", "https")})
    opener = urllib.request.build_opener(proxy)
    try:
        with opener.open("https://ipinfo.io/json", timeout=10) as r:
            j = json.loads(r.read())
        print(f"{j.get('ip')}  {j.get('country', '')} {j.get('city', '')}  {j.get('org', '')}")
    except (urllib.error.URLError, OSError) as e:
        die(f"через прокси не получилось: {e}")


def cmd_log(st, a):
    if IS_WIN:
        service_log = protected_runtime() / "sing-box.log"
        path = service_log if service_log.exists() else LOG_FILE
        while a.follow and not path.exists():
            time.sleep(0.5)
            if service_log.exists():
                path = service_log
        if not path.exists():
            print(f"журнала пока нет: {path}")
            return
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in deque(stream, maxlen=max(0, a.lines)):
                print(line, end="", flush=a.follow)
            while a.follow:
                if line := stream.readline():
                    print(line, end="", flush=True)
                else:
                    time.sleep(0.5)
        return
    cmd = ["journalctl", "-u", UNIT, "-n", str(a.lines), "--no-pager"] + (["-f"] if a.follow else [])
    if getattr(a, "replace", True):
        os.execvp(cmd[0], cmd)
    else:
        run(cmd, check=False)


def cmd_enable(st, a):
    was_running = service_running(st)
    if was_running:
        refuse_other_brand(st, False)
    if not require_windows_admin():
        return
    prepare_service(st)
    restart_if_was_running(st, was_running)
    if IS_WIN:
        register_windows_service(True)
        task_call("change", UPDATE, "/enable", capture=False)
        print(f"✓ автозапуск включён (задачи {BASE} и {UPDATE})")
    else:
        systemctl("enable", UNIT, f"{UPDATE}.timer", sudo=True)
        print(f"✓ автозапуск включён ({UNIT} + {UPDATE}.timer)")
    if a.now and not is_active(st):
        cmd_up(st, argparse.Namespace(force=False))


def cmd_disable(st, a):
    if not require_windows_admin():
        return
    if IS_WIN:
        if task_definition(BASE) is not None:
            register_windows_service(False)
        if a.timer and task_definition(UPDATE) is not None:
            task_call("change", UPDATE, "/disable", capture=False)
        print("✓ автозапуск выключен (работающий VPN не тронут)")
        return
    systemctl("disable", UNIT, sudo=True)
    if a.timer:
        systemctl("disable", f"{UPDATE}.timer", sudo=True)
    print("✓ автозапуск выключен (работающий VPN не тронут)")


def cmd_mode(st, a):
    if a.mode:
        st["settings"]["mode"] = a.mode
        save_state(st)
        apply(st)
    print(st["settings"]["mode"])


def cmd_route(st, a):
    if a.route:
        if (app := st.get("_axiom")) and app["root"]:
            die("маршрут читается из региона приложения AxiOm; измените регион в приложении")
        st["settings"]["route"] = a.route
        save_state(st)
        if a.route == "ru":
            update_rulesets(st)
        apply(st)
    print(effective_route(st))


DOMAIN_KEYS = ("proxy_domains", "direct_domains")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9-]{1,63}$")


def norm_domain(d):
    """«*.Example.RU.» → «example.ru»: правило domain_suffix и так ловит поддомены."""
    return d.strip().lower().removeprefix("*.").strip(".")


def norm_item(key, v):
    """Привести элемент списка к виду, в котором он хранится; мусор — сразу ошибка,
    а не отказ sing-box при следующем apply."""
    v = v.strip()
    if key == "exclude":
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            die(f"exclude — только IP или подсеть, а не «{v}». "
                f"Домен мимо VPN: sbx rule direct {norm_domain(v) or v}")
    if key in DOMAIN_KEYS:
        g = v.lower()
        if g.split(":", 1)[0] in GEO_URL:
            if not GEO_RE.match(g):
                die(f"не rule-set: «{v}» (пример: geosite:google, geoip:telegram)")
            return g
        d = norm_domain(v)
        try:
            ipaddress.ip_network(d, strict=False)
        except ValueError:
            pass
        else:
            die(f"«{v}» — адрес, а не домен. Мимо VPN: sbx set exclude --add {d}")
        try:
            d = d.encode("idna").decode() if not d.isascii() else d
        except UnicodeError:
            die(f"не домен: «{v}»")
        if not DOMAIN_RE.match(d):
            die(f"не домен: «{v}»")
        return d
    return v


def split_items(key, values):
    out = []
    for chunk in values or []:
        out += [norm_item(key, x) for x in chunk.split(",") if x.strip()]
    return list(dict.fromkeys(out))


def commit_settings(st, changed):
    """Проверить конфиг и только потом сохранить: отвергнутое sing-box в state.json не попадает."""
    new = [t for t in map(geo_tag, rule_items(st)) if t and not (RULESET_DIR / f"{t}.srs").exists()]
    if new and (failed := update_rulesets(st, only=set(new))):
        die(f"нет такого списка или он не скачался: {', '.join(failed)} — ничего не изменено")
    if all_servers(st):
        apply(st)
    save_state(st)
    if set(changed) & {"bypass_sports", "bypass_users", "before_units"}:
        if not IS_WIN:
            install_units(st)
        if IS_WIN:
            warn("Windows: bypass_sports, bypass_users и before_units не применяются")
        elif set(changed) & {"bypass_sports", "bypass_users"}:
            print("  правила обхода применятся при следующем sbx restart")


def cmd_set(st, a):
    s = st["settings"]
    if not a.key:
        for k, v in s.items():
            if k != "api_secret":
                print(f"{k} = {json.dumps(v, ensure_ascii=False)}")
        return
    if a.key not in s:
        die(f"нет настройки {a.key}")
    if a.key == "via_rules" and (a.add or a.rm or a.value is not None):
        die("via_rules меняется через sbx rule via ЦЕЛЬ ДОМЕН… / sbx rule rm ДОМЕН…")
    cur = s[a.key]
    if a.add or a.rm:
        if not isinstance(cur, list):
            die(f"{a.key} — не список: --add/--rm только для списков")
        if a.value is not None:
            die("либо значение целиком, либо --add/--rm")
        add, rm = split_items(a.key, a.add), split_items(a.key, a.rm)
        for x in rm:
            if x not in cur:
                warn(f"{x} нет в {a.key}")
        for x in add:
            if x in cur:
                warn(f"{x} уже в {a.key}")
        val = [x for x in cur if x not in rm] + [x for x in add if x not in cur]
    elif a.value is None:
        print(json.dumps(cur, ensure_ascii=False))
        return
    elif isinstance(cur, list):
        if a.value == "default":
            val = DEFAULT_STATE["settings"][a.key]
        else:
            val = split_items(a.key, [a.value])
    elif isinstance(cur, int):
        val = int(a.value)
    else:
        val = a.value
    s[a.key] = val
    commit_settings(st, [a.key])
    print(f"{a.key} = {json.dumps(val, ensure_ascii=False)}")


def via_label(st, to):
    """Как показать цель via-правила; для группы — и сервер, выбранный в ней сейчас."""
    if not to.startswith("re:"):
        return to
    label = f"лучший из /{to[3:]}/"
    if is_active(st):
        try:
            now = api(st, "GET", "/proxies/" + urllib.parse.quote(VIA_PREFIX + to[3:], safe=""),
                      timeout=2).get("now")
            if now:
                label += f" → {now}"
        except (urllib.error.URLError, OSError, ValueError):
            pass
    return label


def parse_via_target(st, q):
    """Цель из командной строки: номер/часть имени сервера, auto, proxy, direct или re:REGEX."""
    if q in ("proxy", "direct"):
        return q
    if q.startswith("re:"):
        try:
            re.compile(q[3:])
        except re.error as e:
            die(f"плохое регулярное выражение {q[3:]!r}: {e}")
        if not any(re.search(q[3:], s["tag"], re.I) for s in all_servers(st)):
            die(f"под /{q[3:]}/ не подходит ни один сервер (sbx ls)")
        return q
    return resolve(st, q, hidden_exact=True)


def drop_items(s, items):
    """Убрать элементы из всех списков правил; пустые via-правила исчезают."""
    for key in DOMAIN_KEYS:
        s[key] = [d for d in s.get(key, []) if d not in items]
    s["via_rules"] = [{**v, "items": [d for d in v["items"] if d not in items]}
                      for v in s.get("via_rules", [])]
    s["via_rules"] = [v for v in s["via_rules"] if v["items"]]


def cmd_rule(st, a):
    s = st["settings"]
    if a.action in (None, "ls"):
        if a.domains:
            die("sbx rule ls — без аргументов")
        for key, title in (("direct_domains", "напрямую"), ("proxy_domains", "через VPN (proxy)")):
            items = s.get(key, [])
            print(f"{title}: {', '.join(items) if items else '—'}")
        for v in s.get("via_rules", []):
            print(f"через {via_label(st, v['to'])}: {', '.join(v['items'])}")
        route = effective_route(st)
        print(f"остальное: route {route}"
              + (" (российское напрямую, прочее через VPN)" if route == "ru" else " (всё через VPN)"))
        print("порядок: напрямую → proxy → via → route; первое совпадение побеждает")
        return
    to = None
    if a.action == "via":
        if not a.domains:
            die("sbx rule via ЦЕЛЬ ДОМЕН|geosite:ИМЯ…")
        to = parse_via_target(st, a.domains.pop(0))
    if not a.domains:
        die(f"sbx rule {a.action} {'ЦЕЛЬ ' if to else ''}ДОМЕН…")
    doms = split_items("proxy_domains", a.domains)
    if a.action == "rm":
        known = set(rule_items(st))
        for d in doms:
            if d not in known:
                warn(f"{d}: такого правила нет")
        doms = [d for d in doms if d in known]
        if not doms:
            return
        drop_items(s, doms)
    else:
        drop_items(s, doms)
        if to is None:
            key = "proxy_domains" if a.action == "proxy" else "direct_domains"
            s[key] = [*s.get(key, []), *doms]
        else:
            same = [v for v in s["via_rules"] if v["to"] == to]
            if same:
                same[0]["items"] += doms
            else:
                s["via_rules"].append({"to": to, "items": doms})
    commit_settings(st, [*DOMAIN_KEYS, "via_rules"])
    where = {"proxy": "через VPN (proxy)", "direct": "напрямую", "rm": "по общим правилам"}.get(
        a.action) or f"через {via_label(st, to)}"
    print(f"✓ {', '.join(doms)} — {where}")


def service_running(st):
    return task_running() if IS_WIN else is_active(st)


def restart_if_was_running(st, was_running):
    """install/enable переписывают конфиг службы без перезагрузки: работающему движку нужен перезапуск."""
    if was_running:
        service_action("restart")
        print("↻ служба перезапущена с новым конфигом")


def cmd_install(st, a):
    was_running = service_running(st)
    if was_running:
        refuse_other_brand(st, getattr(a, "force", False))   # перезапуск запустит движок с новым режимом
    if not require_windows_admin(["install", *(["--force"] if getattr(a, "force", False) else [])]):
        return
    prepare_service(st)
    restart_if_was_running(st, was_running)


def cmd_uninstall(st, a):
    if not require_windows_admin():
        return
    failures = []

    def attempt(what, cmd, **kw):
        result = run(cmd, check=False, **kw)
        if result.returncode:
            failures.append(what)
        return result

    if IS_WIN:
        for name in (BASE, UPDATE):
            try:
                if not task_listed(name):
                    continue
            except OSError as e:
                failures.append(f"запрос задачи {name} ({e})")
                continue
            state = task_state(name)
            if state == "unknown":   # не удалять то, что, возможно, ещё работает
                failures.append(f"состояние задачи {name} неизвестно (задача оставлена)")
                continue
            if state == "running":
                if task_call("end", name, check=False).returncode:
                    failures.append(f"остановка задачи {name}")
                    continue
                for _ in range(20):
                    state = task_state(name)
                    if state != "running":
                        break
                    time.sleep(0.25)
                if state != "stopped":
                    failures.append(f"задача {name} не остановилась" if state == "running" else
                                    f"остановка задачи {name} не подтверждена (задача оставлена)")
                    continue
            attempt(f"удаление задачи {name}", ["schtasks", "/delete", "/tn", name, "/f"])
        if failures:
            die("не удалось: " + ", ".join(failures))
        print(f"✓ задачи удалены; подписки и настройки остались в {CONF_DIR}")
        return
    names = [UNIT, f"{UPDATE}.service", f"{UPDATE}.timer"]
    present = [name for name in names if (UNIT_DIR / name).exists()]
    if present:
        stoppable = [n for n in (f"{UPDATE}.timer", f"{UPDATE}.service") if n in present]
        if stoppable:   # таймер раньше службы, чтобы он не запустил её снова
            attempt("остановка обновления подписок", sudo_cmd("systemctl", "stop", *stoppable))
        attempt("остановка юнитов", sudo_cmd("systemctl", "disable", "--now",
                                             *[n for n in present if n != f"{UPDATE}.service"]))
        for name in present:
            attempt(f"удаление {name}", sudo_cmd("rm", "-f", str(UNIT_DIR / name)))
        attempt("daemon-reload", sudo_cmd("systemctl", "daemon-reload"))
    if BASE == "axiom" and POLKIT_RULE.exists():
        attempt("удаление правила polkit", sudo_cmd("rm", "-f", str(POLKIT_RULE)))
    if failures:
        die("не удалось выполнить: " + ", ".join(failures))
    print(f"✓ юниты удалены; подписки и настройки остались в {CONF_DIR}" if present
          else f"юниты {BASE} не установлены; подписки и настройки остались в {CONF_DIR}")


def cmd_config(st, a):
    apply(st, reload=False)
    if a.show:
        print(CONFIG_FILE.read_text(encoding="utf-8"))
    else:
        ok, err = check_config(CONFIG_FILE)
        print(f"{CONFIG_FILE}: {'ok' if ok else err}")
        if not ok:
            sys.exit(1)


GUIDE = {
    "start": "Сохраните подписку: axiom import URL. Затем axiom connect. Для отключения: axiom disconnect.",
    "commands": "Список команд: axiom --help. Серверы: axiom ls. Подписки: axiom sub ls.",
    "windows": "Скачайте sbx-windows-amd64.exe и переименуйте в axiom.exe. Ядро: axiom core install. Для TUN нужен UAC.",
    "linux": "Установите sing-box и Python 3.9+. Сохраните sbx.py как axiom в PATH и добавьте право на запуск.",
    "tun": "Режим tun направляет трафик всей системы через VPN. Перед подключением закройте другой TUN-клиент.",
    "update": "Версия CLI: axiom update --check, установка: axiom update. Подписки: axiom sub update.",
    "troubleshoot": "Проверьте axiom status, axiom log и axiom config. Задержки без TUN: axiom test.",
}


def cmd_guide(st, a):
    print(GUIDE[a.topic])
    if a.topic == "start":
        print("Темы: " + ", ".join(GUIDE))


def import_name(url):
    host = urllib.parse.urlsplit(url).hostname
    return re.sub(r'[^a-zA-Z0-9._-]', '-', host).strip('.') if host else "axiom"


def cmd_import(st, a):
    source = a.source
    if urllib.parse.urlsplit(source).scheme.lower() in {"http", "https"}:
        name = import_name(source) or "axiom"
        taken = {sub["name"] for sub in st["subs"]}
        base, index = name, 2
        while name in taken:
            name = f"{base}-{index}"
            index += 1
        app = st.get("_axiom")
        # с приложением имя профиля берётся из заголовков панели, а не из хоста
        cmd_sub(st, argparse.Namespace(action="add", name=None if app and app["root"] else name,
                                       url=source, ua=None, no_hwid=False))
        return
    path = Path(source).expanduser().resolve(strict=True)
    if (app := st.get("_axiom")) and app["root"]:
        name = write_axiom_profile(app, name="axiom", local=path)
        print(f"✓ {name}: импортирована")
        apply(st)
        return
    name, index = "axiom", 2
    taken = {sub["name"] for sub in st["subs"]}
    while name in taken:
        name, index = f"axiom-{index}", index + 1
    sub = {"name": name, "local_path": str(path)}
    servers, errors, _, meta = fetch_sub(st, sub)
    if not servers:
        die("в файле нет поддерживаемых серверов")
    if errors:
        warn(f"в файле пропущено записей: {len(errors)}")
    write_private(sub_file(name), json.dumps({"servers": servers, "meta": meta}, ensure_ascii=False, indent=1))
    st["subs"].append(sub)
    save_state(st)
    apply(st)
    print(f"✓ {name}: импортирована")


def cmd_connect(st, a):
    force = getattr(a, "force", False)
    refuse_other_brand(st, force)   # раньше выбора: отказ не должен менять сохранённый выбор
    if getattr(a, "select", None):
        if a.number is not None:
            die("укажите либо номер, либо --select")
        cmd_use(st, argparse.Namespace(server=None, select=a.select))
    elif a.number is not None:
        cmd_use(st, argparse.Namespace(server=str(a.number)))
    elif interactive() and cmd_pick(st, a) is None:
        return
    cmd_up(st, argparse.Namespace(force=force))


def update_arguments(parser, *, self_update=False):
    if self_update:
        parser.add_argument("--check", action="store_true", help="только проверить")
        parser.add_argument("--yes", action="store_true", help="установить без вопроса")
    else:
        parser.add_argument("names", nargs="*")
        parser.add_argument("-q", "--quiet", action="store_true")
    parser.set_defaults(func=cmd_self_update if self_update else cmd_update)


def take_elevated_prefix(argv):
    """Скрытые флаги повышенного запуска (только после --elevated-for) -> (повышенный ли запуск, остаток argv)."""
    global PARENT_INTERACTIVE
    argv = list(argv)
    flags, branded = {}, False
    while argv and (argv[0] in ELEVATED_ENV or argv[0] in {"--elevated-for", "--elevated-interactive", "--axiom"}):
        flag = argv.pop(0)
        if flag == "--axiom":
            branded = True
            continue
        if not argv:
            die(f"{flag} требует значение")
        flags[flag] = argv.pop(0)
    PARENT_INTERACTIVE = flags.get("--elevated-interactive") == "1" and "--elevated-for" in flags
    if "--elevated-interactive" in flags and "--elevated-for" not in flags:
        die("--elevated-interactive допустим только вместе с --elevated-for")
    if "--elevated-for" in flags:
        if not IS_WIN or not windows_admin() or windows_user_sid() != flags["--elevated-for"]:
            die("UAC требует повышение прав той же учётной записи Windows")
    elif set(flags) & set(ELEVATED_ENV) and (windows_admin() if IS_WIN else is_root()):
        die("в привилегированном процессе скрытые флаги допустимы только после --elevated-for")
    for flag, key in ELEVATED_ENV.items():
        if flag in flags:
            os.environ[key] = flags[flag]
    if branded:
        os.environ["SBX_BRAND"] = "axiom"
    if flags or branded:
        configure_identity(axiom_mode())
    return "--elevated-for" in flags, argv


def pause_on_failure(code):
    """Повышенный процесс живёт в своём окне: при ошибке оставить его открытым, пока не нажмут Enter."""
    if not code or not PARENT_INTERACTIVE or sys.stdin is None or not sys.stdin.isatty():
        return   # родитель без человека (скрипт, CI) ждёт код выхода — окно не задерживаем
    print(f"\nОшибка (код {code}). Нажмите Enter, чтобы закрыть окно…", file=sys.stderr, flush=True)
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def exit_status(exc):
    code = exc.code
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    print(code, file=sys.stderr)
    return 1


def main(argv=None):
    global NO_ELEVATE
    remove_old_exe()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        elevated, argv = take_elevated_prefix(argv)
    except SystemExit as e:
        if "--elevated-for" in argv and IS_WIN and windows_admin():
            pause_on_failure(exit_status(e))
        raise
    if "--no-elevate" in argv:
        argv = [item for item in argv if item != "--no-elevate"]
        NO_ELEVATE = True
    if not elevated:
        return run_cli(argv)
    try:
        run_cli(argv)
        code = 0
    except SystemExit as e:
        code = exit_status(e)
    except Exception:
        import traceback
        traceback.print_exc()
        code = 1
    pause_on_failure(code)
    if code:
        sys.exit(code)


def run_cli(argv):
    branded = axiom_mode()
    prog = "axiom" if branded else "sbx"
    p = argparse.ArgumentParser(prog=prog, description=__doc__.split("\n")[0],
                                epilog=__doc__.split("\n\n", 1)[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-V", "--version", action="version", version=f"{prog} {__version__}")
    p.add_argument("--no-elevate", action="store_true",
                   help="Windows: не запрашивать UAC; если нужны права — сообщить и выйти с кодом 2")
    sp = p.add_subparsers(dest="cmd", metavar="команда")

    update_arguments(sp.add_parser("self-update", help="обновить сам sbx из GitHub Releases"), self_update=True)
    sp.add_parser("version", help="версия CLI").set_defaults(func=lambda st, a: print(f"{prog} {__version__}"))
    x = sp.add_parser("guide", help="краткое руководство")
    x.add_argument("topic", nargs="?", choices=GUIDE, default="start")
    x.set_defaults(func=cmd_guide)
    x = sp.add_parser("import", help="импорт подписки по URL или из файла")
    x.add_argument("source")
    x.set_defaults(func=cmd_import)
    x = sp.add_parser("connect", help="выбрать сервер и подключиться; 0 — авто")
    x.add_argument("number", nargs="?", type=int)
    x.add_argument("--select", metavar="C|P|T", help="AxiOm: сервер тройкой СТРАНА|ПРОТОКОЛ|ТРАНСПОРТ")
    x.add_argument("-f", "--force", action="store_true", help="даже если работает другой VPN")
    x.set_defaults(func=cmd_connect)

    x = sp.add_parser("core", help="установка ядра sing-box (Windows)")
    x.add_argument("action", choices=["install"])
    x.set_defaults(func=cmd_core)

    s = sp.add_parser("sub", help="подписки: ls | add ИМЯ URL | rm ИМЯ | update")
    s.set_defaults(func=cmd_sub, action="ls", verbose=False)
    ssp = s.add_subparsers(dest="action")
    x = ssp.add_parser("add", help="добавить подписку и скачать")
    x.add_argument("name")
    x.add_argument("url")
    x.add_argument("--ua", help="свой User-Agent (формат ответа панели зависит от него)")
    x.add_argument("--no-hwid", action="store_true", help="не слать x-hwid и данные устройства")
    x = ssp.add_parser("rm", help="удалить подписку")
    x.add_argument("name")
    x = ssp.add_parser("ls", help="список с трафиком и сроком")
    x.add_argument("-v", "--verbose", action="store_true", help="показать URL")
    update_arguments(ssp.add_parser("update", help="обновить подписки (все или указанные)"))
    update_arguments(sp.add_parser("update", help="обновить CLI" if branded else "обновить подписки"), self_update=branded)

    x = sp.add_parser("add", help="добавить сервер(ы) по URI без подписки")
    x.add_argument("uris", nargs="+")
    x.add_argument("-n", "--name", help="имя сервера")
    x.set_defaults(func=cmd_add)

    x = sp.add_parser("rm", help="удалить добавленный вручную сервер")
    x.add_argument("server")
    x.set_defaults(func=cmd_rm)

    x = sp.add_parser("ls", help="серверы (● выбран, › активный в auto)")
    x.add_argument("filter", nargs="?")
    x.set_defaults(func=cmd_ls)

    x = sp.add_parser("use", help="выбрать сервер: номер, часть имени или auto; без аргумента — меню")
    x.add_argument("server", nargs="?")
    x.add_argument("--select", metavar="C|P|T", help="AxiOm: сервер тройкой СТРАНА|ПРОТОКОЛ|ТРАНСПОРТ")
    x.set_defaults(func=cmd_use_or_pick)
    sp.add_parser("pick", help="интерактивный выбор сервера (↑↓, пробел — пинг, Enter)"
                  ).set_defaults(func=cmd_pick)

    x = sp.add_parser("test", help="задержка до серверов")
    x.add_argument("filter", nargs="?")
    x.add_argument("-t", "--timeout", type=float, default=5, help="секунд на сервер (5)")
    x.set_defaults(func=cmd_test)

    x = sp.add_parser("up", help="включить VPN")
    x.add_argument("-f", "--force", action="store_true", help="даже если работает другой VPN")
    x.set_defaults(func=cmd_up)
    sp.add_parser("down", aliases=["disconnect"], help="выключить VPN").set_defaults(func=cmd_down)
    x = sp.add_parser("restart", help="перезапустить")
    x.add_argument("-f", "--force", action="store_true", help="даже если работает другой VPN")
    x.set_defaults(func=cmd_restart)
    x = sp.add_parser("status", help="состояние")
    x.add_argument("--json", action="store_true", help="машинный вывод")
    x.set_defaults(func=cmd_status)
    sp.add_parser("ip", help="внешний IP через VPN").set_defaults(func=cmd_ip)
    x = sp.add_parser("probe", help="проверить ядро, TUN и подписку без перехвата трафика")
    x.add_argument("-a", "--all", action="store_true", help="проверить все серверы")
    x.set_defaults(func=cmd_probe)

    x = sp.add_parser("log", help="журнал sing-box")
    x.add_argument("-f", "--follow", action="store_true")
    x.add_argument("-n", "--lines", type=int, default=50)
    x.set_defaults(func=cmd_log)

    x = sp.add_parser("enable", help="автозапуск при загрузке")
    x.add_argument("--now", action="store_true", help="и сразу включить")
    x.set_defaults(func=cmd_enable)
    x = sp.add_parser("disable", help="снять с автозапуска")
    x.add_argument("--timer", action="store_true", help="и таймер обновления подписок")
    x.set_defaults(func=cmd_disable)

    x = sp.add_parser("mode", help="tun — весь трафик, proxy — только 127.0.0.1:порт")
    x.add_argument("mode", nargs="?", choices=["tun", "proxy"])
    x.set_defaults(func=cmd_mode)
    x = sp.add_parser("route", help="ru — российское напрямую, global — всё через VPN")
    x.add_argument("route", nargs="?", choices=["ru", "global"])
    x.set_defaults(func=cmd_route)
    x = sp.add_parser("rule", help="свои правила: ls | proxy ДОМЕН… | direct ДОМЕН… "
                                   "| via ЦЕЛЬ ДОМЕН… | rm ДОМЕН…; вместо домена — geosite:ИМЯ, geoip:ИМЯ")
    x.add_argument("action", nargs="?", choices=["ls", "proxy", "direct", "via", "rm"])
    x.add_argument("domains", nargs="*", metavar="домен")
    x.set_defaults(func=cmd_rule)
    x = sp.add_parser("set", help="настройки: sbx set [ключ [значение | --add X | --rm X]]")
    x.add_argument("key", nargs="?")
    x.add_argument("value", nargs="?")
    x.add_argument("--add", action="append", metavar="X[,Y]", help="добавить в список-настройку")
    x.add_argument("--rm", action="append", metavar="X[,Y]", help="убрать из списка-настройки")
    x.set_defaults(func=cmd_set)

    x = sp.add_parser("config", help="проверить сгенерированный конфиг")
    x.add_argument("--show", action="store_true", help="напечатать (там ключи!)")
    x.set_defaults(func=cmd_config)
    x = sp.add_parser("install", help="(пере)установить службу или задачи; работающую — перезапустить")
    x.add_argument("-f", "--force", action="store_true", help="даже если работает другой VPN")
    x.set_defaults(func=cmd_install)
    sp.add_parser("uninstall", help="удалить службу или задачи, данные оставить").set_defaults(func=cmd_uninstall)

    a = p.parse_args(argv)
    if not a.cmd:
        a = p.parse_args(["status"])
    try:
        if a.cmd in {"version", "guide"} or a.func is cmd_self_update:
            a.func(None, a)
            return
        st = load_state()
        if branded:
            if a.cmd in SERVICE_ONLY_COMMANDS:
                st["_axiom"] = empty_axiom_context()   # служебные команды не читают данные приложения
            else:
                try:
                    st["_axiom"] = load_axiom_context()
                except (OSError, ValueError) as e:
                    if a.cmd != "status":
                        raise
                    warn(f"данные приложения AxiOm недоступны: {e}")
                    st["_axiom"] = empty_axiom_context()
        if not STATE_FILE.exists():
            save_state(st)
        if st.get("pending_fetch") and a.cmd not in SERVICE_ONLY_COMMANDS | {"status", "sub", "update", "import"}:
            retry_pending_fetch(st)
        a.func(st, a)
        if st.get("_reload_windows"):
            print("Для применения нового конфига надо перезапустить задачу sbx (UAC).", flush=True)
            request_windows_admin(["restart"])
        maybe_notice_update(st, a)
    except subprocess.CalledProcessError as e:
        die(f"команда завершилась с ошибкой: {' '.join(map(str, e.cmd))}")
    except (OSError, ValueError, KeyError, ImportError, sqlite3.Error, zipfile.BadZipFile, ET.ParseError) as e:
        die(str(e))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
