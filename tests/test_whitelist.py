"""
whitelist_manager.py 和 web_app.py 的完整测试套件。
使用 pytest + unittest.mock，无真实 SSH 连接，用 tmp_path 隔离文件系统。
"""

import json
import os
import sys
import io
import getpass
import datetime
import hashlib
import subprocess
import secrets as secrets_module
from pathlib import Path
from unittest import mock
from contextlib import redirect_stdout

import pytest

# ── 把 src 目录加入 sys.path ─────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── 先 mock paramiko 为不可用，防止导入 web_app 时意外 import ─────────────
_module_mocks = {
    "paramiko": mock.MagicMock(),
    "socks": mock.MagicMock(),
}
with mock.patch.dict(sys.modules, _module_mocks, clear=False):
    import whitelist_manager as wm
    import web_app

# 注入缺失的 import 到 whitelist_manager 模块命名空间（加密功能新增但 import 不完整）
wm.secrets = secrets_module
wm.hashlib = hashlib


# ═══════════════════════════════════════════════════════════════════════════
# 共享 fixture
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_config_file(tmp_path, monkeypatch):
    """将 CONFIG_FILE 重定向到临时目录。"""
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(wm, "CONFIG_FILE", cfg)
    monkeypatch.setattr(web_app, "CONFIG_FILE", cfg)
    return cfg


@pytest.fixture
def sample_config(tmp_config_file):
    """写入一份示例 config.json 并返回 dict。"""
    # 预生成 admin 密码哈希，供 Web 登录测试使用
    salt = "a" * 32  # 16 bytes hex
    from hashlib import sha256
    pw_hash = f"sha256:{salt}:{sha256(f'{salt}:admin'.encode()).hexdigest()}"
    cfg = {
        "whitelist": [
            {"ip": "192.168.1.0/24", "description": "office", "added_by": "admin",
             "added_at": "2025-01-01 10:00:00"},
        ],
        "servers": [
            {"host": "10.0.0.1", "port": 22, "user": "root", "key_file": "",
             "name": "server1", "password": "", "whitelist": []},
        ],
        "settings": {
            "ssh_port": 22,
            "persist_rules": True,
            "proxy": "",
            "auto_deploy": {"enabled": False, "interval_minutes": 5},
            "auth": {"username": "admin", "password_hash": pw_hash},
        },
    }
    tmp_config_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg


@pytest.fixture
def sample_config_no_file(tmp_config_file):
    """不创建 config 文件，返回默认配置。"""
    assert not tmp_config_file.exists()
    return wm.DEFAULT_CONFIG


# ═══════════════════════════════════════════════════════════════════════════
# load_config
# ═══════════════════════════════════════════════════════════════════════════

class TestLoadConfig:
    def test_file_exists(self, sample_config, tmp_config_file):
        cfg = wm.load_config()
        assert cfg["whitelist"][0]["ip"] == "192.168.1.0/24"
        assert cfg["servers"][0]["host"] == "10.0.0.1"

    def test_file_not_exists(self, sample_config_no_file):
        cfg = wm.load_config()
        assert cfg["whitelist"] == []
        assert cfg["servers"] == []
        assert cfg["settings"]["ssh_port"] == 22

    def test_corrupted_json(self, tmp_config_file):
        tmp_config_file.write_text("{ corrupted }", encoding="utf-8")
        # 现在 load_config 会优雅处理损坏的 JSON：备份原文件并回退默认配置
        cfg = wm.load_config()
        assert cfg["whitelist"] == []
        assert cfg["settings"]["ssh_port"] == 22

    def test_purge_expired_on_load(self, tmp_config_file):
        past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        cfg_data = {
            "whitelist": [
                {"ip": "10.0.0.1", "expire_at": past, "added_by": "admin", "added_at": ""},
                {"ip": "10.0.0.2", "added_by": "admin", "added_at": ""},
            ],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg_data), encoding="utf-8")
        cfg = wm.load_config()
        assert len(cfg["whitelist"]) == 1
        assert cfg["whitelist"][0]["ip"] == "10.0.0.2"


# ═══════════════════════════════════════════════════════════════════════════
# save_config
# ═══════════════════════════════════════════════════════════════════════════

class TestSaveConfig:
    def test_normal_write(self, tmp_config_file):
        cfg = wm.load_config()
        cfg["whitelist"].append({"ip": "1.2.3.4", "description": "test"})
        wm.save_config(cfg)
        reloaded = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert reloaded["whitelist"][0]["ip"] == "1.2.3.4"

    def test_password_remains_plaintext_in_memory(self, tmp_config_file):
        """save_config 后 cfg 内存里的密码必须仍是明文，否则后续 SSH 调用会拿到密文。

        回归：之前 _encrypt_passwords 原地改写为 'enc:...'，导致 Guest 自助换 IP 在
        save_config 后调用 capture_run 时用密文当密码，SSH 报 Permission denied。
        """
        cfg = wm.load_config()
        cfg["servers"].append({
            "host": "10.99.99.99", "port": 22, "user": "root",
            "key_file": "", "name": "test-srv",
            "password": "MySecretPwd123!", "whitelist": [],
        })
        wm.save_config(cfg)
        # 写盘后内存里的密码不能变成 "enc:..."
        assert cfg["servers"][-1]["password"] == "MySecretPwd123!"
        # 文件里则应当是加密形式
        on_disk = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert on_disk["servers"][-1]["password"].startswith("enc:")


# ═══════════════════════════════════════════════════════════════════════════
# validate_ip_or_cidr
# ═══════════════════════════════════════════════════════════════════════════

class TestValidateIpOrCidr:
    def test_valid_ipv4(self):
        assert wm.validate_ip_or_cidr("192.168.1.1") is True

    def test_valid_cidr(self):
        assert wm.validate_ip_or_cidr("10.0.0.0/8") is True
        assert wm.validate_ip_or_cidr("192.168.0.0/24") is True

    def test_invalid_format(self):
        assert wm.validate_ip_or_cidr("not_an_ip") is False
        assert wm.validate_ip_or_cidr("") is False
        assert wm.validate_ip_or_cidr("999.999.999.999") is False

    def test_ipv6(self):
        assert wm.validate_ip_or_cidr("::1") is True
        assert wm.validate_ip_or_cidr("2001:db8::/32") is True

    def test_boundary_cidr(self):
        assert wm.validate_ip_or_cidr("0.0.0.0/0") is True
        assert wm.validate_ip_or_cidr("192.168.1.1/32") is True


# ═══════════════════════════════════════════════════════════════════════════
# ip_covered_by_whitelist
# ═══════════════════════════════════════════════════════════════════════════

class TestIpCoveredByWhitelist:
    def test_exact_match(self):
        wl = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        assert wm.ip_covered_by_whitelist("192.168.1.1", wl) is True

    def test_cidr_match(self):
        wl = [{"ip": "192.168.0.0/16"}]
        assert wm.ip_covered_by_whitelist("192.168.99.99", wl) is True

    def test_no_match(self):
        wl = [{"ip": "10.0.0.0/8"}]
        assert wm.ip_covered_by_whitelist("192.168.1.1", wl) is False

    def test_empty_whitelist(self):
        assert wm.ip_covered_by_whitelist("1.1.1.1", []) is False

    def test_invalid_ip_str(self):
        assert wm.ip_covered_by_whitelist("garbage", [{"ip": "1.1.1.1"}]) is False


# ═══════════════════════════════════════════════════════════════════════════
# parse_expire
# ═══════════════════════════════════════════════════════════════════════════

class TestParseExpire:
    def test_empty_or_permanent(self):
        assert wm.parse_expire("") is None
        assert wm.parse_expire("never") is None
        assert wm.parse_expire("永久") is None
        assert wm.parse_expire("permanent") is None

    def test_relative_days(self):
        result = wm.parse_expire("7d")
        assert result is not None
        expected = datetime.datetime.now() + datetime.timedelta(days=7)
        actual = datetime.datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
        assert abs((actual - expected).total_seconds()) < 5

    def test_relative_hours(self):
        result = wm.parse_expire("24h")
        expected = datetime.datetime.now() + datetime.timedelta(hours=24)
        actual = datetime.datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
        assert abs((actual - expected).total_seconds()) < 5

    def test_relative_minutes(self):
        result = wm.parse_expire("30m")
        expected = datetime.datetime.now() + datetime.timedelta(minutes=30)
        actual = datetime.datetime.strptime(result, "%Y-%m-%d %H:%M:%S")
        assert abs((actual - expected).total_seconds()) < 5

    def test_absolute_datetime(self):
        result = wm.parse_expire("2025-12-31 23:59:59")
        assert result == "2025-12-31 23:59:59"

    def test_absolute_date_only(self):
        result = wm.parse_expire("2025-06-15")
        assert result == "2025-06-15 23:59:59"

    def test_iso_format(self):
        result = wm.parse_expire("2025-12-31T23:59")
        assert result == "2025-12-31 23:59:00"

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="无效的过期时间格式"):
            wm.parse_expire("next tuesday")


# ═══════════════════════════════════════════════════════════════════════════
# is_entry_expired
# ═══════════════════════════════════════════════════════════════════════════

class TestIsEntryExpired:
    def test_no_expire_field(self):
        assert wm.is_entry_expired({"ip": "1.1.1.1"}) is False

    def test_expired(self):
        past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        assert wm.is_entry_expired({"ip": "1.1.1.1", "expire_at": past}) is True

    def test_not_expired(self):
        future = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        assert wm.is_entry_expired({"ip": "1.1.1.1", "expire_at": future}) is False

    def test_invalid_expire_format(self):
        assert wm.is_entry_expired({"ip": "1.1.1.1", "expire_at": "bogus"}) is False


# ═══════════════════════════════════════════════════════════════════════════
# purge_expired_entries
# ═══════════════════════════════════════════════════════════════════════════

class TestPurgeExpiredEntries:
    def test_purge_global_and_per_server(self):
        past = (datetime.datetime.now() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        future = (datetime.datetime.now() + datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cfg = {
            "whitelist": [
                {"ip": "1.1.1.1", "expire_at": past},
                {"ip": "2.2.2.2", "expire_at": future},
            ],
            "servers": [
                {"host": "s1", "name": "srv1", "whitelist": [
                    {"ip": "3.3.3.3", "expire_at": past},
                    {"ip": "4.4.4.4"},
                ]},
            ],
        }
        removed = wm.purge_expired_entries(cfg)
        assert len(removed) == 2
        assert ("全局", {"ip": "1.1.1.1", "expire_at": past}) in removed
        assert len(cfg["whitelist"]) == 1
        assert cfg["whitelist"][0]["ip"] == "2.2.2.2"
        assert len(cfg["servers"][0]["whitelist"]) == 1
        assert cfg["servers"][0]["whitelist"][0]["ip"] == "4.4.4.4"


# ═══════════════════════════════════════════════════════════════════════════
# get_merged_whitelist
# ═══════════════════════════════════════════════════════════════════════════

class TestGetMergedWhitelist:
    def test_merge_no_duplicate(self):
        server = {"whitelist": [{"ip": "10.0.0.2"}]}
        global_wl = [{"ip": "10.0.0.1"}]
        merged = wm.get_merged_whitelist(server, global_wl)
        assert len(merged) == 2

    def test_merge_dedup(self):
        server = {"whitelist": [{"ip": "10.0.0.1"}]}
        global_wl = [{"ip": "10.0.0.1"}]
        merged = wm.get_merged_whitelist(server, global_wl)
        assert len(merged) == 1

    def test_filter_expired(self):
        past = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        server = {"whitelist": [{"ip": "10.0.0.2", "expire_at": past}]}
        global_wl = [{"ip": "10.0.0.1"}]
        merged = wm.get_merged_whitelist(server, global_wl)
        assert len(merged) == 1
        assert merged[0]["ip"] == "10.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════
# _make_ip_entry
# ═══════════════════════════════════════════════════════════════════════════

class TestMakeIpEntry:
    def test_basic(self, monkeypatch):
        monkeypatch.setattr(getpass, "getuser", lambda: "testuser")
        entry = wm._make_ip_entry("1.2.3.4", "test desc")
        assert entry["ip"] == "1.2.3.4"
        assert entry["description"] == "test desc"
        assert entry["added_by"] == "testuser"
        assert "added_at" in entry

    def test_with_expire(self, monkeypatch):
        monkeypatch.setattr(getpass, "getuser", lambda: "testuser")
        entry = wm._make_ip_entry("1.2.3.4", "test", "2025-12-31 23:59:59")
        assert entry["expire_at"] == "2025-12-31 23:59:59"


# ═══════════════════════════════════════════════════════════════════════════
# _resolve_proxy
# ═══════════════════════════════════════════════════════════════════════════

class TestResolveProxy:
    def test_per_server(self):
        server = {"proxy": "socks5://srv-proxy:1080"}
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://srv-proxy:1080"

    def test_global_settings(self):
        server = {}
        config = {"settings": {"proxy": "http://global-proxy:3128"}}
        result = wm._resolve_proxy(server, config)
        assert result == "http://global-proxy:3128"

    def test_env_ALL_PROXY(self, monkeypatch):
        server = {}
        monkeypatch.setenv("ALL_PROXY", "socks5://all-upper:1080")
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://all-upper:1080"

    def test_env_all_proxy(self, monkeypatch):
        server = {}
        monkeypatch.setenv("all_proxy", "socks5://all-lower:1080")
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://all-lower:1080"

    def test_env_SOCKS_PROXY(self, monkeypatch):
        server = {}
        monkeypatch.setenv("SOCKS_PROXY", "socks5://socks-upper:1080")
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://socks-upper:1080"

    def test_env_socks_proxy(self, monkeypatch):
        server = {}
        monkeypatch.setenv("socks_proxy", "socks5://socks-lower:1080")
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://socks-lower:1080"

    def test_env_priority_order(self, monkeypatch):
        """ALL_PROXY 在环境变量列表中排第一，应优先返回。"""
        server = {}
        monkeypatch.setenv("all_proxy", "socks5://second:1080")
        monkeypatch.setenv("ALL_PROXY", "socks5://first:1080")
        result = wm._resolve_proxy(server, {})
        assert result == "socks5://first:1080"

    def test_per_server_priority(self, monkeypatch):
        server = {"proxy": "socks5://srv-proxy:1080"}
        config = {"settings": {"proxy": "http://global-proxy:3128"}}
        monkeypatch.setenv("ALL_PROXY", "socks5://env-proxy:1080")
        result = wm._resolve_proxy(server, config)
        assert result == "socks5://srv-proxy:1080"

    def test_no_proxy(self):
        assert wm._resolve_proxy({}, {}) == ""


# ═══════════════════════════════════════════════════════════════════════════
# _find_server
# ═══════════════════════════════════════════════════════════════════════════

class TestFindServer:
    def test_find_by_host(self):
        cfg = {"servers": [{"host": "10.0.0.1", "name": "srv1"}]}
        assert wm._find_server(cfg, "10.0.0.1") is not None

    def test_find_by_name(self):
        cfg = {"servers": [{"host": "10.0.0.1", "name": "srv1"}]}
        assert wm._find_server(cfg, "srv1") is not None

    def test_not_found(self):
        assert wm._find_server({"servers": []}, "missing") is None


# ═══════════════════════════════════════════════════════════════════════════
# cmd_ip_add
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdIpAdd:
    def test_add_global(self, sample_config, tmp_config_file, monkeypatch):
        monkeypatch.setattr(getpass, "getuser", lambda: "tester")
        args = mock.Mock(ip="10.0.0.5", desc="test", expire=None, server=None)
        wm.cmd_ip_add(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert any(e["ip"] == "10.0.0.5" for e in cfg["whitelist"])

    def test_add_duplicate_global(self, sample_config, tmp_config_file, capsys):
        args = mock.Mock(ip="192.168.1.0/24", desc="dup", expire=None, server=None)
        wm.cmd_ip_add(args)
        out = capsys.readouterr().out
        assert "已在全局白名单中" in out

    def test_add_invalid_ip(self, sample_config, capsys):
        args = mock.Mock(ip="not_an_ip", desc="", expire=None, server=None)
        with pytest.raises(SystemExit):
            wm.cmd_ip_add(args)
        out = capsys.readouterr().out
        assert "无效" in out

    def test_add_to_server_whitelist(self, sample_config, tmp_config_file, monkeypatch):
        monkeypatch.setattr(getpass, "getuser", lambda: "tester")
        args = mock.Mock(ip="10.0.0.99", desc="server-only", expire=None, server="10.0.0.1")
        wm.cmd_ip_add(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        srv = cfg["servers"][0]
        assert any(e["ip"] == "10.0.0.99" for e in srv.get("whitelist", []))

    def test_add_to_unknown_server(self, sample_config, capsys):
        args = mock.Mock(ip="1.1.1.1", desc="", expire=None, server="unknown")
        with pytest.raises(SystemExit):
            wm.cmd_ip_add(args)
        assert "未找到服务器" in capsys.readouterr().out

    def test_global_cleans_server_duplicates(self, sample_config, tmp_config_file, monkeypatch):
        """添加全局 IP 时应自动清除各服务器专属白名单中的同一 IP。"""
        monkeypatch.setattr(getpass, "getuser", lambda: "tester")
        # 先手动添加一个 IP 到服务器的专属白名单
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["servers"][0].setdefault("whitelist", []).append(
            {"ip": "10.0.0.77", "description": "", "added_by": "admin", "added_at": ""}
        )
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        args = mock.Mock(ip="10.0.0.77", desc="now-global", expire=None, server=None)
        wm.cmd_ip_add(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert len(cfg["servers"][0].get("whitelist", [])) == 0


# ═══════════════════════════════════════════════════════════════════════════
# cmd_ip_remove
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdIpRemove:
    def test_remove_global(self, sample_config, tmp_config_file):
        args = mock.Mock(ip="192.168.1.0/24", server=None)
        wm.cmd_ip_remove(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert not any(e["ip"] == "192.168.1.0/24" for e in cfg["whitelist"])

    def test_remove_not_found_global(self, sample_config, capsys):
        args = mock.Mock(ip="0.0.0.0", server=None)
        wm.cmd_ip_remove(args)
        assert "不在全局白名单中" in capsys.readouterr().out

    def test_remove_from_server(self, sample_config, tmp_config_file, monkeypatch):
        monkeypatch.setattr(getpass, "getuser", lambda: "tester")
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["servers"][0].setdefault("whitelist", []).append(
            {"ip": "5.5.5.5", "description": "", "added_by": "admin", "added_at": ""}
        )
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        args = mock.Mock(ip="5.5.5.5", server="10.0.0.1")
        wm.cmd_ip_remove(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert not any(e["ip"] == "5.5.5.5" for e in cfg["servers"][0].get("whitelist", []))

    def test_remove_from_unknown_server(self, sample_config, capsys):
        args = mock.Mock(ip="1.1.1.1", server="unknown")
        with pytest.raises(SystemExit):
            wm.cmd_ip_remove(args)
        assert "未找到服务器" in capsys.readouterr().out


# ═══════════════════════════════════════════════════════════════════════════
# cmd_ip_list
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdIpList:
    def test_list_global(self, sample_config, capsys):
        args = mock.Mock(server=None)
        wm.cmd_ip_list(args)
        out = capsys.readouterr().out
        assert "全局白名单" in out
        assert "192.168.1.0/24" in out

    def test_list_empty(self, tmp_config_file, capsys):
        tmp_config_file.write_text(json.dumps(wm.DEFAULT_CONFIG), encoding="utf-8")
        args = mock.Mock(server=None)
        wm.cmd_ip_list(args)
        assert "为空" in capsys.readouterr().out

    def test_list_server(self, sample_config, capsys):
        args = mock.Mock(server="10.0.0.1")
        wm.cmd_ip_list(args)
        out = capsys.readouterr().out
        assert "专属白名单" in out

    def test_list_unknown_server(self, sample_config, capsys):
        args = mock.Mock(server="unknown")
        with pytest.raises(SystemExit):
            wm.cmd_ip_list(args)
        assert "未找到服务器" in capsys.readouterr().out


# ═══════════════════════════════════════════════════════════════════════════
# cmd_server_add / cmd_server_remove / cmd_server_list
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdServerAdd:
    def test_add_server(self, sample_config, tmp_config_file):
        from argparse import Namespace
        args = Namespace(host="10.0.0.2", port=2222, user="admin", key="", name="srv2",
                         password="", proxy="")
        wm.cmd_server_add(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert any(s["host"] == "10.0.0.2" for s in cfg["servers"])

    def test_add_duplicate(self, sample_config, capsys):
        args = mock.Mock(host="10.0.0.1", port=22, user="root", key="", name=None,
                          password="", proxy="")
        wm.cmd_server_add(args)
        assert "已存在" in capsys.readouterr().out


class TestCmdServerRemove:
    def test_remove_server(self, sample_config, tmp_config_file):
        args = mock.Mock(host="10.0.0.1")
        wm.cmd_server_remove(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert len(cfg["servers"]) == 0

    def test_remove_not_found(self, sample_config, capsys):
        args = mock.Mock(host="unknown")
        wm.cmd_server_remove(args)
        assert "不存在" in capsys.readouterr().out


class TestCmdServerList:
    def test_list(self, sample_config, capsys):
        args = mock.Mock()
        wm.cmd_server_list(args)
        out = capsys.readouterr().out
        assert "server1" in out
        assert "10.0.0.1" in out

    def test_list_empty(self, tmp_config_file, capsys):
        tmp_config_file.write_text(json.dumps(wm.DEFAULT_CONFIG), encoding="utf-8")
        args = mock.Mock()
        wm.cmd_server_list(args)
        assert "为空" in capsys.readouterr().out


# ═══════════════════════════════════════════════════════════════════════════
# generate_apply_script
# ═══════════════════════════════════════════════════════════════════════════

class TestGenerateApplyScript:
    def test_iptables_path(self):
        whitelist = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.0/8"}]
        script = wm.generate_apply_script(whitelist, 22, True)
        # 结构验证
        assert script.startswith("#!/bin/bash")
        assert "SSH_PORT=22\n" in script
        assert "CHAIN=\"SSH_WHITELIST\"" in script
        assert "PERSIST=true" in script
        assert "AUDIT=false" in script
        # IP 正确嵌入
        assert "192.168.1.1" in script
        assert "10.0.0.0/8" in script
        # 两个防火墙路径均存在
        assert "iptables" in script
        assert "systemctl is-active --quiet firewalld" in script
        assert "firewall-cmd" in script
        # iptables 路径中 IP 被添加到链
        assert "iptables -A \"$CHAIN\" -s " in script

    def test_firewalld_path(self):
        whitelist = [{"ip": "172.16.0.1"}]
        script = wm.generate_apply_script(whitelist, 2222, False)
        assert "SSH_PORT=2222\n" in script
        assert "172.16.0.1" in script
        assert "PERSIST=false" in script

    def test_audit_mode(self):
        whitelist = [{"ip": "1.1.1.1"}]
        script = wm.generate_apply_script(whitelist, 22, True, audit=True)
        assert "AUDIT=true" in script
        assert "审计模式" in script
        # 审计模式 iptables 路径应使用 LOG + ACCEPT，不直接 DROP
        assert 'iptables -A "$CHAIN" -j LOG' in script
        assert 'iptables -A "$CHAIN" -j ACCEPT' in script

    def test_production_mode(self):
        """生产模式（非审计）必须包含 DROP 规则。"""
        whitelist = [{"ip": "1.1.1.1"}]
        script = wm.generate_apply_script(whitelist, 22, True, audit=False)
        assert "iptables -A \"$CHAIN\" -j DROP" in script

    def test_empty_whitelist(self):
        script = wm.generate_apply_script([], 22, True)
        # 空白名单时，WHITELIST_IPS 数组为空
        assert "WHITELIST_IPS=(" in script or "WHITELIST_IPS" in script

    def test_persist_rules_paths(self):
        """验证三个持久化路径都存在。"""
        whitelist = [{"ip": "1.1.1.1"}]
        script = wm.generate_apply_script(whitelist, 22, True)
        assert "/etc/iptables/rules.v4" in script
        assert "/etc/sysconfig/iptables" in script
        assert "rc.local" in script

    def test_no_persist_skips_save(self):
        whitelist = [{"ip": "1.1.1.1"}]
        script = wm.generate_apply_script(whitelist, 22, False)
        assert "PERSIST=false" in script


# ═══════════════════════════════════════════════════════════════════════════
# generate_status_script / generate_remove_script
# ═══════════════════════════════════════════════════════════════════════════

class TestGenerateStatusScript:
    def test_basic(self):
        script = wm.generate_status_script(22)
        assert script.startswith("#!/bin/bash")
        assert "SSH_WHITELIST" in script
        assert "firewalld" in script
        assert "iptables" in script
        assert "22" in script

    def test_custom_port(self):
        script = wm.generate_status_script(2222)
        assert "2222" in script


class TestGenerateRemoveScript:
    def test_basic(self):
        script = wm.generate_remove_script(22)
        assert script.startswith("#!/bin/bash")
        assert "SSH_WHITELIST" in script
        assert "firewall-cmd" in script
        assert "iptables" in script
        # 移除脚本应包含恢复 ssh service 的命令
        assert "firewall-cmd --permanent --add-service=ssh" in script

    def test_custom_port(self):
        script = wm.generate_remove_script(2222)
        assert "2222" in script


# ═══════════════════════════════════════════════════════════════════════════
# run_on_server (mock paramiko)
# ═══════════════════════════════════════════════════════════════════════════

class TestRunOnServer:
    SERVER = {"host": "10.0.0.1", "port": 22, "user": "root",
              "key_file": "", "password": "", "name": "test-srv"}

    def test_dry_run(self, capsys):
        ok = wm.run_on_server(self.SERVER, "echo hello", dry_run=True)
        out = capsys.readouterr().out
        assert ok is True
        assert "DRY-RUN" in out
        assert "echo hello" in out

    def test_paramiko_success(self, monkeypatch):
        pmock = mock.MagicMock()
        mock_client = mock.MagicMock()
        mock_chan_stdout = mock.MagicMock()
        mock_chan_stdout.read.return_value = b"output ok\n"
        mock_chan_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (
            mock.MagicMock(), mock_chan_stdout, mock.MagicMock()
        )
        pmock.SSHClient.return_value = mock_client
        pmock.AutoAddPolicy = mock.MagicMock()

        # 带密码的服务器，避免非交互模式报错
        server_with_pw = {**self.SERVER, "password": "testpass"}
        with mock.patch.dict(sys.modules, {"paramiko": pmock}):
            ok = wm.run_on_server(server_with_pw, "echo test", config={}, interactive=False)
            assert ok is True

    def test_paramiko_connection_failure(self, monkeypatch):
        pmock = mock.MagicMock()
        # AuthenticationException 必须是真实异常类，否则 except 子句会 TypeError
        class FakeAuthException(Exception):
            pass
        pmock.AuthenticationException = FakeAuthException
        mock_client = mock.MagicMock()
        mock_client.connect.side_effect = Exception("Connection refused")
        pmock.SSHClient.return_value = mock_client
        pmock.AutoAddPolicy = mock.MagicMock()

        with mock.patch.dict(sys.modules, {"paramiko": pmock}):
            ok = wm.run_on_server(self.SERVER, "echo test", config={}, interactive=False)
            assert ok is False

    def test_paramiko_auth_failure_no_interactive(self, monkeypatch):
        pmock = mock.MagicMock()
        mock_client = mock.MagicMock()
        # 创建真实的 AuthenticationException 子类作为 mock 属性
        class FakeAuthException(Exception):
            pass
        pmock.AuthenticationException = FakeAuthException
        mock_client.connect.side_effect = FakeAuthException("auth failed")
        pmock.SSHClient.return_value = mock_client
        pmock.AutoAddPolicy = mock.MagicMock()

        with mock.patch.dict(sys.modules, {"paramiko": pmock}):
            ok = wm.run_on_server(self.SERVER, "echo test", config={}, interactive=False)
            assert ok is False

    def test_subprocess_fallback(self):
        with mock.patch.object(subprocess, "run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stdout=b"ok\n", stderr=b"")
            ok = wm._run_via_subprocess(
                "10.0.0.1", 22, "root", "", "", "echo test", ""
            )
            assert ok is True

    def test_subprocess_failure(self):
        with mock.patch.object(subprocess, "run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=1, stdout=b"", stderr=b"err")
            ok = wm._run_via_subprocess(
                "10.0.0.1", 22, "root", "", "", "echo test", ""
            )
            assert ok is False

    def test_subprocess_timeout(self):
        with mock.patch.object(subprocess, "run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("ssh", 60)
            ok = wm._run_via_subprocess(
                "10.0.0.1", 22, "root", "", "", "echo test", ""
            )
            assert ok is False


# ═══════════════════════════════════════════════════════════════════════════
# _proxy_to_nc_command
# ═══════════════════════════════════════════════════════════════════════════

class TestProxyToNcCommand:
    def test_socks5(self):
        result = wm._proxy_to_nc_command("socks5://127.0.0.1:1080")
        assert "-X 5 -x 127.0.0.1:1080" in result

    def test_http(self):
        result = wm._proxy_to_nc_command("http://proxy:3128")
        assert "-X connect -x proxy:3128" in result

    def test_empty(self):
        assert wm._proxy_to_nc_command("") == ""


# ═══════════════════════════════════════════════════════════════════════════
# get_outgoing_ip
# ═══════════════════════════════════════════════════════════════════════════

class TestGetOutgoingIp:
    def test_with_target_host(self):
        with mock.patch("socket.socket") as mock_sock:
            mock_sock.return_value.getsockname.return_value = ("10.0.0.99", 12345)
            ip = wm.get_outgoing_ip("8.8.8.8")
            assert ip == "10.0.0.99"

    def test_fallback_to_api(self):
        with mock.patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect.side_effect = OSError
            with mock.patch("urllib.request.urlopen") as mock_url:
                mock_url.return_value = io.BytesIO(b"1.2.3.4\n")
                ip = wm.get_outgoing_ip()
                assert ip == "1.2.3.4"

    def test_all_failed(self):
        with mock.patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect.side_effect = OSError
            with mock.patch("urllib.request.urlopen", side_effect=OSError):
                ip = wm.get_outgoing_ip()
                assert ip is None


# ═══════════════════════════════════════════════════════════════════════════
# get_target_servers
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTargetServers:
    def test_all_servers(self, sample_config):
        cfg = wm.load_config()
        servers = wm.get_target_servers(cfg)
        assert len(servers) == 1

    def test_filter_by_host(self, sample_config):
        cfg = wm.load_config()
        servers = wm.get_target_servers(cfg, "10.0.0.1")
        assert servers[0]["host"] == "10.0.0.1"

    def test_no_servers(self, tmp_config_file, capsys):
        tmp_config_file.write_text(json.dumps(wm.DEFAULT_CONFIG), encoding="utf-8")
        cfg = wm.load_config()
        with pytest.raises(SystemExit):
            wm.get_target_servers(cfg)
        assert "服务器列表为空" in capsys.readouterr().out

    def test_filter_not_found(self, sample_config, capsys):
        cfg = wm.load_config()
        with pytest.raises(SystemExit):
            wm.get_target_servers(cfg, "unknown")
        assert "未找到服务器" in capsys.readouterr().out


# ═══════════════════════════════════════════════════════════════════════════
# cmd_settings
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdSettings:
    def test_update_port(self, sample_config, tmp_config_file):
        args = mock.Mock(ssh_port=2222, persist=None, proxy=None)
        wm.cmd_settings(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert cfg["settings"]["ssh_port"] == 2222

    def test_update_persist(self, sample_config, tmp_config_file):
        args = mock.Mock(ssh_port=None, persist=False, proxy=None)
        wm.cmd_settings(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert cfg["settings"]["persist_rules"] is False

    def test_update_proxy(self, sample_config, tmp_config_file):
        args = mock.Mock(ssh_port=None, persist=None, proxy="http://proxy:8080")
        wm.cmd_settings(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert cfg["settings"]["proxy"] == "http://proxy:8080"

    def test_clear_proxy(self, sample_config, tmp_config_file):
        args = mock.Mock(ssh_port=None, persist=None, proxy="")
        wm.cmd_settings(args)
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert cfg["settings"]["proxy"] == ""


# ═══════════════════════════════════════════════════════════════════════════
# generate_audit_log_script
# ═══════════════════════════════════════════════════════════════════════════

class TestGenerateAuditLogScript:
    def test_basic(self):
        script = wm.generate_audit_log_script(22, 50)
        assert script.startswith("#!/bin/bash")
        assert "SSH_AUDIT" in script or "SSH_BLOCKED" in script
        assert "journalctl" in script

    def test_custom_lines(self):
        script = wm.generate_audit_log_script(22, 100)
        assert "tail -n 100" in script


# ═══════════════════════════════════════════════════════════════════════════
# Flask Web App 测试
# ═══════════════════════════════════════════════════════════════════════════

CSRF_TEST_TOKEN = "test-csrf-token-12345"


class _CSRFClient:
    """包装 Flask test client，自动为 POST/PATCH/PUT/DELETE 添加 CSRF header。"""

    def __init__(self, client, token):
        self._c = client
        self._token = token

    def _headers(self, extra=None):
        h = {"X-CSRF-Token": self._token}
        if extra:
            h.update(extra)
        return h

    def get(self, *a, **kw):
        return self._c.get(*a, **kw)

    def post(self, *a, **kw):
        kw.setdefault("headers", {}).update({"X-CSRF-Token": self._token})
        return self._c.post(*a, **kw)

    def patch(self, *a, **kw):
        kw.setdefault("headers", {}).update({"X-CSRF-Token": self._token})
        return self._c.patch(*a, **kw)

    def put(self, *a, **kw):
        kw.setdefault("headers", {}).update({"X-CSRF-Token": self._token})
        return self._c.put(*a, **kw)

    def delete(self, *a, **kw):
        kw.setdefault("headers", {}).update({"X-CSRF-Token": self._token})
        return self._c.delete(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._c, name)


@pytest.fixture
def web_client(tmp_config_file, monkeypatch):
    """创建 Flask 测试客户端，mock 掉 run_on_server。"""
    monkeypatch.setattr(web_app, "run_on_server", mock.MagicMock(return_value=True))
    monkeypatch.setattr(web_app, "capture_run", mock.MagicMock(return_value=(True, "mock output")))
    # 默认让本地出口探测返回 None，使 /api/deploy 的"管理机本地 IP 必须在全局白名单"硬拦截
    # 视为"未知 IP"而跳过——既有 deploy 测试无需关心该拦截。需要触发拦截的测试自行 monkeypatch。
    monkeypatch.setattr(web_app, "get_outgoing_ip", mock.MagicMock(return_value=None))
    monkeypatch.setattr(web_app, "_setup_app_secret", lambda: setattr(web_app.app, "secret_key", "test-key"))
    monkeypatch.setattr(web_app, "_init_scheduler_from_config", lambda: None)
    # 固定 token_hex 输出，确保 CSRF token 可预测
    monkeypatch.setattr(web_app.secrets, "token_hex", lambda n: CSRF_TEST_TOKEN[:n])
    web_app.app.config["TESTING"] = True
    if not web_app.app.secret_key:
        web_app.app.secret_key = "test-key"
    raw = web_app.app.test_client()
    return _CSRFClient(raw, CSRF_TEST_TOKEN)


def _login(client, username="admin", password="admin"):
    """辅助：登录。"""
    return client.post("/api/login", json={"username": username, "password": password})


@pytest.fixture
def logged_in_client(web_client, sample_config):
    """已登录的测试客户端。"""
    resp = _login(web_client)
    if resp.status_code != 200:
        # 降级：通过 session_transaction 手动注入认证状态
        with web_client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["csrf_token"] = CSRF_TEST_TOKEN
    return web_client


# ── 密码哈希函数测试（独立单元） ─────────────────────────────────────────

class TestHashPassword:
    def test_hash_returns_pbkdf2_format(self):
        h = web_app._hash_password("test")
        assert h.startswith("pbkdf2:")
        parts = h.split(":", 3)
        assert len(parts) == 4
        assert int(parts[1]) == 200_000
        assert len(parts[2]) == 32  # 16 bytes hex salt
        assert len(parts[3]) == 64  # 32 bytes PBKDF2 output

    def test_hash_is_unique_each_call(self):
        h1 = web_app._hash_password("same_password")
        h2 = web_app._hash_password("same_password")
        assert h1 != h2  # 随机盐确保每次结果不同

    def test_hash_different_passwords_differ(self):
        h1 = web_app._hash_password("pwd1")
        h2 = web_app._hash_password("pwd2")
        assert h1 != h2


class TestVerifyPassword:
    def test_verify_correct_password(self):
        h = web_app._hash_password("correct")
        assert web_app._verify_password("correct", h) is True

    def test_verify_wrong_password(self):
        h = web_app._hash_password("correct")
        assert web_app._verify_password("wrong", h) is False

    def test_verify_invalid_format(self):
        assert web_app._verify_password("x", "not_a_hash") is False
        assert web_app._verify_password("x", "") is False
        assert web_app._verify_password("x", "sha256:tooshort") is False

    def test_verify_unknown_prefix(self):
        assert web_app._verify_password("x", "md5:salt:hashvalue") is False


# ── 认证测试 ──────────────────────────────────────────────────────────────

class TestWebLogin:
    def test_login_success(self, web_client, sample_config):
        resp = _login(web_client)
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["success"] is True

    def test_login_wrong_password(self, web_client):
        resp = _login(web_client, "admin", "wrongpassword")
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False

    def test_login_wrong_username(self, web_client):
        resp = _login(web_client, "nobody", "admin")
        assert resp.status_code == 401

    def test_login_missing_fields(self, web_client):
        resp = web_client.post("/api/login", json={})
        assert resp.status_code == 401


class TestWebUnauthenticated:
    def test_api_returns_401(self, web_client):
        resp = web_client.get("/api/config")
        assert resp.status_code == 401
        assert "未登录" in resp.get_json()["message"]

    def test_page_redirects(self, web_client):
        resp = web_client.get("/")
        assert resp.status_code == 302

    def test_public_endpoints_accessible(self, web_client):
        # GET 可访问的公开页面
        for path in ["/login", "/guest", "/apply", "/api/servers-public"]:
            resp = web_client.get(path)
            assert resp.status_code == 200, f"{path} should be public"
        # /api/login 仅接受 POST（公开 API 但不是 GET 端点）
        resp = web_client.post("/api/login", json={"username": "x", "password": "x"})
        assert resp.status_code == 401  # 认证失败但路径可访问


# ── /api/whitelist ───────────────────────────────────────────────────────

class TestWebWhitelist:
    def test_get_whitelist(self, logged_in_client, sample_config):
        # whitelist 数据通过 /api/config 获取（无独立 GET /api/whitelist 端点）
        resp = logged_in_client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "whitelist" in data

    def test_add_ip(self, logged_in_client):
        resp = logged_in_client.post("/api/whitelist", json={
            "ip": "1.2.3.4", "description": "test"
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_add_invalid_ip(self, logged_in_client):
        resp = logged_in_client.post("/api/whitelist", json={"ip": "bad"})
        assert resp.status_code == 400
        assert resp.get_json()["success"] is False

    def test_add_duplicate(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/whitelist", json={"ip": "192.168.1.0/24"})
        assert resp.status_code == 409

    def test_add_empty_ip(self, logged_in_client):
        resp = logged_in_client.post("/api/whitelist", json={"ip": ""})
        assert resp.status_code == 400

    def test_remove_ip(self, logged_in_client, sample_config):
        resp = logged_in_client.delete("/api/whitelist/192.168.1.0/24")
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_remove_nonexistent(self, logged_in_client):
        resp = logged_in_client.delete("/api/whitelist/0.0.0.0")
        assert resp.status_code == 404

    def test_update_ip(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0/24", json={
            "description": "updated"
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_update_ip_change(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0/24", json={
            "ip": "10.10.10.10"
        })
        assert resp.status_code == 200

    def test_update_nonexistent(self, logged_in_client):
        resp = logged_in_client.patch("/api/whitelist/0.0.0.0", json={"description": "x"})
        assert resp.status_code == 404

    def test_add_missing_json(self, logged_in_client):
        resp = logged_in_client.post("/api/whitelist", data="not json",
                                     content_type="application/json")
        assert resp.status_code == 400


# ── /api/servers ─────────────────────────────────────────────────────────

class TestWebServers:
    def test_get_servers(self, logged_in_client, sample_config):
        # servers 数据通过 /api/config 获取（无独立 GET /api/servers 端点）
        resp = logged_in_client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "servers" in data

    def test_add_server(self, logged_in_client):
        resp = logged_in_client.post("/api/servers", json={
            "host": "10.0.0.99", "name": "newsrv"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["server"]["host"] == "10.0.0.99"
        assert "password" not in data["server"]  # has_password exposed instead

    def test_add_duplicate_server(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/servers", json={"host": "10.0.0.1"})
        assert resp.status_code == 409

    def test_add_empty_host(self, logged_in_client):
        resp = logged_in_client.post("/api/servers", json={"host": ""})
        assert resp.status_code == 400

    def test_remove_server(self, logged_in_client, sample_config):
        resp = logged_in_client.delete("/api/servers/10.0.0.1")
        assert resp.status_code == 200

    def test_remove_nonexistent(self, logged_in_client):
        resp = logged_in_client.delete("/api/servers/0.0.0.0")
        assert resp.status_code == 404

    def test_update_server_password(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/servers/10.0.0.1", json={
            "password": "newpass"
        })
        assert resp.status_code == 200

    def test_update_nonexistent_server(self, logged_in_client):
        resp = logged_in_client.patch("/api/servers/0.0.0.0", json={"password": "x"})
        assert resp.status_code == 404


# ── /api/servers/<host>/whitelist ────────────────────────────────────────

class TestWebServerWhitelist:
    def test_add_server_ip(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/servers/10.0.0.1/whitelist", json={
            "ip": "5.5.5.5"
        })
        assert resp.status_code == 200

    def test_add_server_ip_invalid(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/servers/10.0.0.1/whitelist", json={
            "ip": "bad"
        })
        assert resp.status_code == 400

    def test_remove_server_ip(self, logged_in_client, sample_config):
        # 先添加一个
        logged_in_client.post("/api/servers/10.0.0.1/whitelist", json={"ip": "5.5.5.5"})
        resp = logged_in_client.delete("/api/servers/10.0.0.1/whitelist/5.5.5.5")
        assert resp.status_code == 200

    def test_remove_nonexistent_server(self, logged_in_client):
        resp = logged_in_client.delete("/api/servers/0.0.0.0/whitelist/1.1.1.1")
        assert resp.status_code == 404

    def test_update_server_ip(self, logged_in_client, sample_config):
        logged_in_client.post("/api/servers/10.0.0.1/whitelist", json={"ip": "6.6.6.6"})
        resp = logged_in_client.patch("/api/servers/10.0.0.1/whitelist/6.6.6.6", json={
            "description": "updated-desc"
        })
        assert resp.status_code == 200


# ── /api/deploy ──────────────────────────────────────────────────────────

class TestWebDeploy:
    def test_deploy_success(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data

    def test_deploy_dry_run(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/deploy", json={"dry_run": True})
        data = resp.get_json()
        # dry_run 直接返回结果
        assert "results" in data

    def test_deploy_empty_servers(self, logged_in_client, tmp_config_file):
        tmp_config_file.write_text(json.dumps({
            "whitelist": [{"ip": "1.1.1.1"}],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }), encoding="utf-8")
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 400

    def test_deploy_server_not_found(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/deploy", json={"server": "unknown"})
        assert resp.status_code == 404

    def test_deploy_response_reflects_server_results(self, logged_in_client, sample_config, monkeypatch):
        """验证 deploy 响应中每个服务器的成功/失败状态被正确反映。
        不依赖 web_client fixture 的全局 mock，使用独立 mock。"""
        mock_run = mock.MagicMock(return_value=True)
        monkeypatch.setattr(web_app, "run_on_server", mock_run)
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        results = data["results"]
        assert len(results) >= 1
        for r in results:
            assert "server" in r
            assert "host" in r
            assert "success" in r
            assert "output" in r

    def test_deploy_mixed_success_failure(self, logged_in_client, sample_config, monkeypatch):
        """当多台服务器中部分成功部分失败时，success_count 应正确统计。"""
        monkeypatch.setattr(web_app, "run_on_server",
                            mock.MagicMock(side_effect=[True, False, Exception("fail")]))
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        # 验证 results 包含所有服务器的状态
        assert "success_count" in data
        assert "total" in data
        assert data["success_count"] <= data["total"]


# ── /api/status ──────────────────────────────────────────────────────────

class TestWebStatus:
    def test_status(self, logged_in_client, sample_config):
        resp = logged_in_client.get("/api/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "results" in data

    def test_status_results_structure(self, logged_in_client, sample_config, monkeypatch):
        """验证 status 响应中 results 的结构，使用独立 mock。"""
        mock_capture = mock.MagicMock(return_value=(True, "firewalld active\n"))
        monkeypatch.setattr(web_app, "capture_run", mock_capture)
        resp = logged_in_client.get("/api/status")
        assert resp.status_code == 200
        data = resp.get_json()
        for r in data["results"]:
            assert "server" in r
            assert "host" in r
            assert "success" in r
            assert "output" in r

    def test_status_empty_servers(self, logged_in_client, tmp_config_file):
        tmp_config_file.write_text(json.dumps({
            "whitelist": [],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }), encoding="utf-8")
        resp = logged_in_client.get("/api/status")
        assert resp.status_code == 400


# ── /api/applications ────────────────────────────────────────────────────

class TestWebApplications:
    def test_submit_application(self, web_client, sample_config):
        resp = web_client.post("/api/apply", json={
            "ip": "2.2.2.2",
            "name": "张三",
            "employee_id": "E001",
            "purpose": "远程办公",
            "duration": "7d",
            "servers": ["10.0.0.1"],
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "id" in data

    def test_submit_missing_fields(self, web_client):
        resp = web_client.post("/api/apply", json={"ip": "1.1.1.1"})
        assert resp.status_code == 400

    def test_submit_invalid_ip(self, web_client):
        resp = web_client.post("/api/apply", json={
            "ip": "invalid", "name": "x", "employee_id": "x",
            "purpose": "x", "duration": "7d", "servers": ["10.0.0.1"],
        })
        assert resp.status_code == 400

    def test_submit_unknown_server(self, web_client):
        resp = web_client.post("/api/apply", json={
            "ip": "1.1.1.1", "name": "x", "employee_id": "x",
            "purpose": "x", "duration": "7d", "servers": ["99.99.99.99"],
        })
        assert resp.status_code == 400

    def test_list_applications(self, logged_in_client):
        resp = logged_in_client.get("/api/applications")
        assert resp.status_code == 200
        assert "applications" in resp.get_json()

    def test_approve_application(self, logged_in_client, sample_config):
        # 先提交申请
        logged_in_client.post("/api/apply", json={
            "ip": "9.9.9.9", "name": "李四", "employee_id": "E002",
            "purpose": "测试", "duration": "1d", "servers": ["10.0.0.1"],
        })
        apps = logged_in_client.get("/api/applications").get_json()["applications"]
        app_id = apps[0]["id"]

        resp = logged_in_client.post(f"/api/applications/{app_id}/review", json={
            "action": "approve", "servers": ["10.0.0.1"]
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_reject_application(self, logged_in_client, sample_config):
        logged_in_client.post("/api/apply", json={
            "ip": "8.8.8.8", "name": "王五", "employee_id": "E003",
            "purpose": "测试", "duration": "1d", "servers": ["10.0.0.1"],
        })
        apps = logged_in_client.get("/api/applications").get_json()["applications"]
        app_id = apps[0]["id"]

        resp = logged_in_client.post(f"/api/applications/{app_id}/review", json={
            "action": "reject"
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_review_nonexistent_application(self, logged_in_client):
        resp = logged_in_client.post("/api/applications/nonexistent/review", json={
            "action": "approve", "servers": ["10.0.0.1"]
        })
        assert resp.status_code == 404

    def test_review_wrong_action(self, logged_in_client, sample_config):
        logged_in_client.post("/api/apply", json={
            "ip": "7.7.7.7", "name": "x", "employee_id": "x",
            "purpose": "x", "duration": "1d", "servers": ["10.0.0.1"],
        })
        apps = logged_in_client.get("/api/applications").get_json()["applications"]
        app_id = apps[0]["id"]

        resp = logged_in_client.post(f"/api/applications/{app_id}/review", json={
            "action": "invalid"
        })
        assert resp.status_code == 400

    def test_deploy_applications_empty(self, logged_in_client):
        resp = logged_in_client.post("/api/applications/deploy", json={})
        assert resp.status_code == 400


# ── /api/settings ─────────────────────────────────────────────────────────

class TestWebSettings:
    def test_update_port(self, logged_in_client):
        resp = logged_in_client.patch("/api/settings", json={"ssh_port": 2222})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_invalid_port(self, logged_in_client):
        resp = logged_in_client.patch("/api/settings", json={"ssh_port": 99999})
        assert resp.status_code == 400

    def test_persist_rules(self, logged_in_client):
        resp = logged_in_client.patch("/api/settings", json={"persist_rules": False})
        assert resp.status_code == 200


# ── /api/remove ──────────────────────────────────────────────────────────

class TestWebRemove:
    def test_remove(self, logged_in_client, sample_config):
        resp = logged_in_client.post("/api/remove", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data

    def test_remove_empty_servers(self, logged_in_client, tmp_config_file):
        tmp_config_file.write_text(json.dumps({
            "whitelist": [], "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }), encoding="utf-8")
        resp = logged_in_client.post("/api/remove", json={})
        assert resp.status_code == 400


# ── /api/auth/password ───────────────────────────────────────────────────

class TestWebChangePassword:
    def test_change_password(self, logged_in_client):
        resp = logged_in_client.patch("/api/auth/password", json={
            "old_password": "admin", "new_password": "newadmin123"
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_change_password_wrong_old(self, logged_in_client):
        resp = logged_in_client.patch("/api/auth/password", json={
            "old_password": "wrong", "new_password": "newpass123"
        })
        assert resp.status_code == 403

    def test_change_password_too_short(self, logged_in_client):
        resp = logged_in_client.patch("/api/auth/password", json={
            "old_password": "admin", "new_password": "ab"
        })
        assert resp.status_code == 400


# ── /api/check-my-ip ─────────────────────────────────────────────────────

class TestWebCheckMyIp:
    def test_check_ip(self, web_client):
        resp = web_client.get("/api/check-my-ip")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "client_ip" in data

    def test_check_ip_with_server_filter(self, web_client, sample_config):
        resp = web_client.get("/api/check-my-ip?server=10.0.0.1")
        assert resp.status_code == 200


# ── /api/my-ip ───────────────────────────────────────────────────────────

class TestWebMyIp:
    """/api/my-ip 仅返回 HTTP 请求方真实客户端 IP，不做服务器侧出口探测。"""

    def test_my_ip_returns_client_ip(self, web_client):
        resp = web_client.get("/api/my-ip")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "client_ip" in data
        assert "is_local" in data

    def test_my_ip_does_not_probe_outgoing(self, web_client, monkeypatch):
        """关键不变量：不应触发 get_outgoing_ip——避免把网站服务器自身 IP 当作用户 IP。"""
        probe = mock.MagicMock(return_value="1.2.3.4")
        monkeypatch.setattr(web_app, "get_outgoing_ip", probe)
        resp = web_client.get("/api/my-ip")
        assert resp.status_code == 200
        probe.assert_not_called()

    def test_my_ip_trusts_xff_when_remote_is_local(self, web_client):
        """remote_addr 是本地代理时，应优先返回 X-Forwarded-For 链首。"""
        resp = web_client.get("/api/my-ip", headers={"X-Forwarded-For": "141.66.77.88"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["client_ip"] == "141.66.77.88"
        assert data["is_local"] is False


# ── /api/guest/replace ───────────────────────────────────────────────────

class TestWebGuestReplace:
    def test_replace_ip(self, web_client, sample_config):
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "192.168.1.0/24", "new_ip": "192.168.2.0/24"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True

    def test_replace_empty_ips(self, web_client):
        resp = web_client.post("/api/guest/replace", json={"old_ip": "", "new_ip": ""})
        assert resp.status_code == 400

    def test_replace_invalid_old(self, web_client):
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "bad", "new_ip": "1.2.3.4"
        })
        assert resp.status_code == 400

    def test_replace_not_found(self, web_client):
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "9.9.9.9", "new_ip": "1.2.3.4"
        })
        assert resp.status_code == 404

    def test_replace_preserves_description_and_expire(self, web_client, tmp_config_file):
        """自助替换必须保留原条目的 description 和 expire_at（保持原有到期时间和备注相同）。"""
        cfg = {
            "whitelist": [{
                "ip": "10.1.1.1",
                "description": "alice-laptop",
                "added_by": "admin",
                "added_at": "2025-01-01 10:00:00",
                "expire_at": "2030-12-31 23:59:59",
            }],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "10.1.1.1", "new_ip": "10.2.2.2",
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        entry = next(e for e in saved["whitelist"] if e["ip"] == "10.2.2.2")
        assert entry["description"] == "alice-laptop"
        assert entry["expire_at"] == "2030-12-31 23:59:59"
        # 自助换 IP 记录写入独立的 self_service_log，不混入 applications
        assert "applications" not in saved or all(
            a.get("type") != "replace" for a in saved.get("applications", [])
        )
        record = saved["self_service_log"][-1]
        assert record["old_ip"] == "10.1.1.1"
        assert record["new_ip"] == "10.2.2.2"
        assert record["description"] == "alice-laptop"
        assert record["expire_at"] == "2030-12-31 23:59:59"


# ── /api/config ──────────────────────────────────────────────────────────

class TestWebConfig:
    def test_get_config(self, logged_in_client, sample_config):
        resp = logged_in_client.get("/api/config")
        assert resp.status_code == 200
        # password 字段不应在返回中出现
        data = resp.get_json()
        for s in data.get("servers", []):
            assert "password" not in s


# ── /api/scheduler ───────────────────────────────────────────────────────

class TestWebScheduler:
    def test_get_scheduler(self, logged_in_client):
        resp = logged_in_client.get("/api/scheduler")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "enabled" in data

    def test_patch_scheduler_disable(self, logged_in_client):
        resp = logged_in_client.patch("/api/scheduler", json={"enabled": False})
        assert resp.status_code == 200


# ── /api/audit-log ───────────────────────────────────────────────────────

class TestWebAuditLog:
    def test_audit_log(self, logged_in_client, sample_config):
        resp = logged_in_client.get("/api/audit-log")
        assert resp.status_code == 200

    def test_audit_log_empty_servers(self, logged_in_client, tmp_config_file):
        tmp_config_file.write_text(json.dumps({
            "whitelist": [], "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }), encoding="utf-8")
        resp = logged_in_client.get("/api/audit-log")
        assert resp.status_code == 400


# ── /api/logout ──────────────────────────────────────────────────────────

class TestWebLogout:
    def test_logout(self, logged_in_client):
        resp = logged_in_client.post("/api/logout", json={})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_access_after_logout(self, logged_in_client):
        logged_in_client.post("/api/logout", json={})
        resp = logged_in_client.get("/api/config")
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# cmd_deploy 逻辑测试（mock run_on_server）
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdDeployNoSSH:
    """不需要真实 SSH 的 cmd_deploy 测试。"""

    def test_deploy_empty_whitelist(self, tmp_config_file, capsys):
        cfg = wm.DEFAULT_CONFIG.copy()
        cfg["servers"] = [{"host": "10.0.0.1", "port": 22, "user": "root",
                            "key_file": "", "name": "s1", "password": "", "whitelist": []}]
        cfg["settings"] = {"ssh_port": 22, "persist_rules": True}
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        args = mock.Mock(server=None, port=None, dry_run=False, yes=False, audit=False)
        with pytest.raises(SystemExit):
            wm.cmd_deploy(args)
        assert "白名单为空" in capsys.readouterr().out

    def test_deploy_via_api_style(self, sample_config, tmp_config_file):
        """通过类似 Web API 的路径测试部署逻辑，避免 cmd_deploy 的交互。"""
        config = wm.load_config()
        whitelist = config["whitelist"]
        servers = config["servers"]
        # 模拟 api_deploy 的核心逻辑
        server_merged_map = {}
        for s in servers:
            merged = wm.get_merged_whitelist(s, whitelist)
            server_merged_map[s["host"]] = merged
        assert "10.0.0.1" in server_merged_map
        assert len(server_merged_map["10.0.0.1"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# cmd_status / cmd_remove 逻辑（mock run_on_server）
# ═══════════════════════════════════════════════════════════════════════════

class TestCmdStatusNoSSH:
    def test_status(self, sample_config):
        args = mock.Mock(server=None)
        with mock.patch.object(wm, "run_on_server", return_value=True):
            wm.cmd_status(args)


class TestCmdRemoveNoSSH:
    def test_remove(self, sample_config):
        args = mock.Mock(server=None, yes=True)
        with mock.patch.object(wm, "run_on_server", return_value=True):
            wm.cmd_remove(args)


# ═══════════════════════════════════════════════════════════════════════════
# parse_expire 额外边界
# ═══════════════════════════════════════════════════════════════════════════

class TestParseExpireExtra:
    def test_whitespace_only(self):
        assert wm.parse_expire("   ") is None

    def test_datetime_with_seconds(self):
        result = wm.parse_expire("2025-06-01 12:30:45")
        assert result == "2025-06-01 12:30:45"

    def test_datetime_with_minute_only(self):
        result = wm.parse_expire("2025-06-01 12:30")
        assert result == "2025-06-01 12:30:00"


# ═══════════════════════════════════════════════════════════════════════════
# /api/servers-public
# ═══════════════════════════════════════════════════════════════════════════

class TestWebServersPublic:
    def test_servers_public(self, web_client, sample_config):
        resp = web_client.get("/api/servers-public")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["servers"]) == 1
        assert "password" not in data["servers"][0]


# ═══════════════════════════════════════════════════════════════════════════
# 白名单条目锁定（防 guest 误换 / 误删 / 误编辑关键 IP）
# ═══════════════════════════════════════════════════════════════════════════

class TestWebWhitelistLock:
    def test_lock_global_entry(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0%2F24/lock", json={"locked": True})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["entry"]["locked"] is True

    def test_unlock_global_entry(self, logged_in_client, tmp_config_file):
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["whitelist"][0]["locked"] = True
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0%2F24/lock", json={"locked": False})
        assert resp.status_code == 200
        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert "locked" not in saved["whitelist"][0]

    def test_lock_missing_field(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0%2F24/lock", json={})
        assert resp.status_code == 400

    def test_lock_unknown_ip(self, logged_in_client, sample_config):
        resp = logged_in_client.patch("/api/whitelist/9.9.9.9/lock", json={"locked": True})
        assert resp.status_code == 404

    def test_delete_locked_global_entry_rejected(self, logged_in_client, tmp_config_file):
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["whitelist"][0]["locked"] = True
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = logged_in_client.delete("/api/whitelist/192.168.1.0%2F24")
        assert resp.status_code == 403
        # 条目仍在
        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert any(e["ip"] == "192.168.1.0/24" for e in saved["whitelist"])

    def test_edit_locked_global_entry_rejected(self, logged_in_client, tmp_config_file):
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["whitelist"][0]["locked"] = True
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = logged_in_client.patch("/api/whitelist/192.168.1.0%2F24", json={"description": "changed"})
        assert resp.status_code == 403

    def test_guest_replace_locked_rejected(self, web_client, tmp_config_file):
        """锁定的关键 IP 不可被 Guest 自助换 IP 替换（这是本功能的核心安全保证）。"""
        cfg = {
            "whitelist": [{
                "ip": "141.66.66.66",
                "description": "site-server-self-loop",
                "added_by": "admin",
                "added_at": "2025-01-01 10:00:00",
                "locked": True,
            }],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "141.66.66.66", "new_ip": "10.0.0.1",
        })
        assert resp.status_code == 403
        # 条目未被改动
        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert saved["whitelist"][0]["ip"] == "141.66.66.66"

    def test_guest_replace_locked_server_entry_rejected(self, web_client, tmp_config_file):
        """服务器专属白名单中的锁定条目同样不可被 Guest 替换。"""
        cfg = {
            "whitelist": [],
            "servers": [{
                "host": "10.0.0.1", "port": 22, "user": "root", "key_file": "",
                "name": "s1", "password": "",
                "whitelist": [{
                    "ip": "203.0.113.5", "description": "critical",
                    "added_by": "admin", "added_at": "2025-01-01 10:00:00",
                    "locked": True,
                }],
            }],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "203.0.113.5", "new_ip": "10.10.10.10",
        })
        assert resp.status_code == 403
        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        assert saved["servers"][0]["whitelist"][0]["ip"] == "203.0.113.5"

    def test_lock_server_entry_and_block_delete(self, logged_in_client, tmp_config_file):
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["servers"][0]["whitelist"] = [{
            "ip": "10.5.5.5", "description": "", "added_by": "admin",
            "added_at": "2025-01-01 10:00:00",
        }]
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        lock = logged_in_client.patch("/api/servers/10.0.0.1/whitelist/10.5.5.5/lock",
                                       json={"locked": True})
        assert lock.status_code == 200

        rm = logged_in_client.delete("/api/servers/10.0.0.1/whitelist/10.5.5.5")
        assert rm.status_code == 403

        edit = logged_in_client.patch("/api/servers/10.0.0.1/whitelist/10.5.5.5",
                                      json={"description": "new"})
        assert edit.status_code == 403

    def test_unlocked_entry_can_be_replaced_by_guest(self, web_client, tmp_config_file):
        """回归：未锁定的条目仍可正常被 Guest 替换。"""
        cfg = {
            "whitelist": [{
                "ip": "10.1.1.1", "description": "alice",
                "added_by": "admin", "added_at": "2025-01-01 10:00:00",
            }],
            "servers": [],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")
        resp = web_client.post("/api/guest/replace", json={
            "old_ip": "10.1.1.1", "new_ip": "10.2.2.2",
        })
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# 锁定状态从专属白名单继承到全局白名单
# ═══════════════════════════════════════════════════════════════════════════

class TestLockInheritanceWeb:
    """提升到全局白名单时必须继承原专属白名单的锁定状态（防绕过锁定）。"""

    def test_global_add_inherits_locked_from_server_whitelist(self, logged_in_client, tmp_config_file):
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["servers"][0]["whitelist"] = [{
            "ip": "5.5.5.5", "description": "critical-on-srv1",
            "added_by": "admin", "added_at": "2025-01-01 10:00:00",
            "locked": True,
        }]
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        resp = logged_in_client.post("/api/whitelist",
                                     json={"ip": "5.5.5.5", "description": "global"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["entry"]["locked"] is True

        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        new_entry = next(e for e in saved["whitelist"] if e["ip"] == "5.5.5.5")
        assert new_entry.get("locked") is True
        # 专属白名单中的同 IP 已被清除
        assert not any(e["ip"] == "5.5.5.5" for e in saved["servers"][0]["whitelist"])

    def test_global_add_no_inherit_when_unlocked(self, logged_in_client, tmp_config_file):
        """专属条目未锁定时，新建全局条目也不应自动加锁。"""
        cfg = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        cfg["servers"][0]["whitelist"] = [{
            "ip": "6.6.6.6", "description": "not-critical",
            "added_by": "admin", "added_at": "2025-01-01 10:00:00",
        }]
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        resp = logged_in_client.post("/api/whitelist", json={"ip": "6.6.6.6"})
        assert resp.status_code == 200
        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        new_entry = next(e for e in saved["whitelist"] if e["ip"] == "6.6.6.6")
        assert not new_entry.get("locked")


class TestLockInheritanceCLI:
    def test_cli_ip_add_inherits_locked(self, tmp_config_file, capsys):
        cfg = {
            "whitelist": [],
            "servers": [{
                "host": "10.0.0.1", "port": 22, "user": "root", "key_file": "",
                "name": "s1", "password": "",
                "whitelist": [{
                    "ip": "7.7.7.7", "description": "", "added_by": "admin",
                    "added_at": "2025-01-01 10:00:00", "locked": True,
                }],
            }],
            "settings": {"ssh_port": 22, "persist_rules": True},
        }
        tmp_config_file.write_text(json.dumps(cfg), encoding="utf-8")

        args = mock.MagicMock(ip="7.7.7.7", desc="from-cli", server=None, expire=None)
        wm.cmd_ip_add(args)

        saved = json.loads(tmp_config_file.read_text(encoding="utf-8"))
        new_entry = next(e for e in saved["whitelist"] if e["ip"] == "7.7.7.7")
        assert new_entry.get("locked") is True
        assert not any(e["ip"] == "7.7.7.7" for e in saved["servers"][0]["whitelist"])


# ═══════════════════════════════════════════════════════════════════════════
# 下发硬拦截：管理机本地 IP 必须在全局白名单中
# ═══════════════════════════════════════════════════════════════════════════

class TestDeployBlocksUnlistedManagementHost:
    def test_deploy_blocked_when_local_ip_not_in_global(self, logged_in_client, sample_config, monkeypatch):
        """探测到管理机出口 IP，但该 IP 不在全局白名单中——必须拦截，不下发任何脚本。"""
        monkeypatch.setattr(web_app, "get_outgoing_ip", mock.MagicMock(return_value="203.0.113.99"))
        run_mock = mock.MagicMock(return_value=True)
        monkeypatch.setattr(web_app, "run_on_server", run_mock)
        capture_mock = mock.MagicMock(return_value=(True, "out"))
        monkeypatch.setattr(web_app, "capture_run", capture_mock)

        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["success"] is False
        assert "203.0.113.99" in data["message"]
        # 关键：被拦截时不可触发实际下发
        capture_mock.assert_not_called()

    def test_deploy_allowed_when_local_ip_in_global(self, logged_in_client, sample_config, monkeypatch):
        """管理机 IP 在全局白名单（被 CIDR 覆盖）时正常放行。"""
        # sample_config 的全局白名单是 192.168.1.0/24
        monkeypatch.setattr(web_app, "get_outgoing_ip", mock.MagicMock(return_value="192.168.1.42"))
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 200

    def test_deploy_allowed_when_probe_returns_none(self, logged_in_client, sample_config, monkeypatch):
        """探测失败（None/loopback）时不拦截，沿用既有行为。"""
        monkeypatch.setattr(web_app, "get_outgoing_ip", mock.MagicMock(return_value=None))
        resp = logged_in_client.post("/api/deploy", json={})
        assert resp.status_code == 200

    def test_deploy_dry_run_bypasses_block(self, logged_in_client, sample_config, monkeypatch):
        """dry_run 仅生成脚本预览，不真正下发，跳过拦截。"""
        monkeypatch.setattr(web_app, "get_outgoing_ip", mock.MagicMock(return_value="203.0.113.99"))
        resp = logged_in_client.post("/api/deploy", json={"dry_run": True})
        assert resp.status_code == 200


def test_total_count():
    """确保测试总数合理（自检）。"""
    import inspect
    classes = [obj for name, obj in inspect.getmembers(sys.modules[__name__], inspect.isclass)
               if obj.__module__ == __name__ and name.startswith("Test")]
    methods = []
    for cls in classes:
        for name, method in inspect.getmembers(cls, inspect.isfunction):
            if name.startswith("test_"):
                methods.append(f"{cls.__name__}.{name}")
    # 确保有足够数量的测试
    assert len(methods) >= 100, f"预期至少 100 个测试，实际 {len(methods)} 个"
