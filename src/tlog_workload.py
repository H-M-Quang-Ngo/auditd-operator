# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The tlog session-recording service module."""

import grp
import logging
import os
import pwd
import subprocess
from pathlib import Path

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from constants import (
    TLOG_BIN,
    TLOG_BIN_MODE,
    TLOG_CONF_FILE,
    TLOG_LOG_DIR,
    TLOG_LOG_DIR_GROUP,
    TLOG_LOG_DIR_MODE,
    TLOG_LOG_DIR_OWNER,
    TLOG_LOG_FILE,
    TLOG_LOG_FILE_GROUP,
    TLOG_LOG_FILE_MODE,
    TLOG_LOG_FILE_OWNER,
    TLOG_LOGROTATE_FILE,
    TLOG_REC_SESSION_CONF_TEMPLATE,
    TLOG_SSHD_CONF_TEMPLATE,
    TLOG_SSHD_SNIPPET,
    TLOG_SYSTEM_GROUP,
    TLOG_SYSTEM_USER,
    TLOG_TEMPLATE_FILE_PATH,
    TLOG_WRAPPER_FILE,
    TLOG_WRAPPER_TEMPLATE,
)
from utils import make_dir, render_jinja2_template, write_file, write_file_with_group

# logrotate config for /var/log/tlog/sessions.log.
# prerotate/postrotate chattr dance: +a forbids rename+truncate so default rotate fails.
# tlog reopens the file per session, so new sessions pick up the rotated path automatically.
_TLOG_LOGROTATE_CONTENT = f"""\
{TLOG_LOG_FILE} {{
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 tlog adm
    prerotate
        chattr -a {TLOG_LOG_FILE} 2>/dev/null || true
    endscript
    postrotate
        chattr +a {TLOG_LOG_FILE} 2>/dev/null || true
    endscript
}}
"""

logger = logging.getLogger(__name__)


class TlogServiceError(Exception):
    """Base error for TlogService failures."""


class TlogServiceReloadError(TlogServiceError):
    """sshd reload or sshd -t validation failure."""


class TlogService:
    """Manages tlog installation, configuration, and sshd wiring."""

    pkg = "tlog"
    sshd_service = "ssh"

    _conf_path = Path(TLOG_CONF_FILE)
    _wrapper_path = Path(TLOG_WRAPPER_FILE)
    _snippet_path = Path(TLOG_SSHD_SNIPPET)
    _log_dir = Path(TLOG_LOG_DIR)
    _log_file = Path(TLOG_LOG_FILE)
    _tlog_bin = Path(TLOG_BIN)
    _logrotate_path = Path(TLOG_LOGROTATE_FILE)

    def install(self) -> None:
        """Install tlog package; raise TlogServiceError if unavailable.

        Raises:
            TlogServiceError: if the tlog package is not available in apt cache
            or apt-cache is not found.

        """
        try:
            result = subprocess.run(
                ["apt-cache", "policy", self.pkg],
                capture_output=True,
                text=True,
                check=False,
            )
            if "Candidate: (none)" in result.stdout or not result.stdout.strip():
                raise TlogServiceError(
                    f"Package '{self.pkg}' is not available. "
                    "Ensure the 'universe' apt pocket is enabled."
                )
        except FileNotFoundError as exc:
            raise TlogServiceError(
                "apt-cache not found; cannot verify tlog availability."
            ) from exc
        apt.add_package(package_names=self.pkg, update_cache=False)

    def remove(self) -> None:
        """Remove tlog package."""
        if self.is_installed():
            apt.remove_package(package_names=self.pkg)

    def is_installed(self) -> bool:
        """Return True if tlog is installed."""
        try:
            apt.DebianPackage.from_installed_package(self.pkg)
        except apt.PackageNotFoundError:
            return False
        return True

    def ensure_log_dir(self) -> None:
        """Ensure /var/log/tlog/ exists with privileged ownership."""
        make_dir(self._log_dir, TLOG_LOG_DIR_OWNER, TLOG_LOG_DIR_GROUP, TLOG_LOG_DIR_MODE)
        if not self._log_file.exists():
            write_file_with_group(
                self._log_file, "", TLOG_LOG_FILE_OWNER, TLOG_LOG_FILE_GROUP, TLOG_LOG_FILE_MODE
            )

    def _ensure_privileged_recorder(self) -> None:
        """Reproduce the upstream setuid configuration.

        Ubuntu installs tlog-rec-session as a plain root:root executable with
        no setuid bit and creates no `tlog` system user. Upstream ships the binary
        mode 6755 owned tlog:tlog
        (https://github.com/Scribery/tlog/blob/006f58ab1af0cb55247f1baf4fcfba08e9870b16/tlog.spec#L124)

        The file writer relies on that setuid privilege-drop: the binary saves the
        privileged tlog euid/egid, drops to the connecting user for the recorded
        shell, then opens the shared sessions.log with the saved tlog privilege.
        Without it the unprivileged recorded user cannot write the tamper-protected
        (tlog:adm 0640) log and recording fails with EACCES.

        Creates the tlog system group+user if absent and restores the setuid
        ownership/mode on the binary. Runs on every reconcile because a package
        upgrade reverts the binary to root:root non-setuid.

        Raises:
            TlogServiceError: user/group creation or binary mode change failed.

        """
        try:
            self._ensure_system_group(TLOG_SYSTEM_GROUP)
            self._ensure_system_user(TLOG_SYSTEM_USER, TLOG_SYSTEM_GROUP)
            uid = pwd.getpwnam(TLOG_SYSTEM_USER).pw_uid
            gid = grp.getgrnam(TLOG_SYSTEM_GROUP).gr_gid
            os.chown(self._tlog_bin, uid, gid)
            os.chmod(self._tlog_bin, TLOG_BIN_MODE)
        except (KeyError, OSError, subprocess.SubprocessError) as exc:
            raise TlogServiceError(
                f"Failed to set up the privileged tlog recorder: {exc}"
            ) from exc

    @staticmethod
    def _ensure_system_group(name: str) -> None:
        """Create a system group if it does not already exist.

        Args:
            name (str): the group name to ensure exists.

        """
        try:
            grp.getgrnam(name)
            return
        except KeyError:
            pass
        subprocess.run(["groupadd", "--system", name], check=True)

    @staticmethod
    def _ensure_system_user(name: str, group: str) -> None:
        """Create a no-login system user in the given group if it does not exist.

        Args:
            name (str): the username to ensure exists.
            group (str): the group name for the user.

        """
        try:
            pwd.getpwnam(name)
            return
        except KeyError:
            pass
        subprocess.run(
            [
                "useradd",
                "--system",
                "--gid",
                group,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                name,
            ],
            check=True,
        )

    def configure(self, groups: str) -> None:
        """Enable or disable tlog recording.

        Args:
            groups: Comma-joined group names from AuditdConfig.session_recording_groups.
                    Empty string disables recording.

        Raises:
            TlogServiceError: wrapper validation failed (no snippet written).
            TlogServiceReloadError: sshd -t or reload failed (snippet reverted).

        """
        if not groups:
            self._disable()
            return

        if not self.is_installed():
            self.install()

        self._ensure_privileged_recorder()
        self.ensure_log_dir()
        self._write_tlog_conf()
        self._write_wrapper_atomic()
        self._write_logrotate()
        self._write_sshd_snippet(groups)

    def _disable(self) -> None:
        """Remove the sshd snippet and reload only if it existed (H3 idempotent)."""
        if not self._snippet_path.exists():
            return
        self._snippet_path.unlink()
        self.reload_sshd()

    def _write_tlog_conf(self) -> None:
        """Write tlog-rec-session.conf if content changed."""
        new_content = render_jinja2_template(
            {"log_file": str(self._log_file)},
            TLOG_REC_SESSION_CONF_TEMPLATE,
            TLOG_TEMPLATE_FILE_PATH,
        )
        current = self._conf_path.read_text(encoding="utf-8") if self._conf_path.exists() else ""
        if new_content.strip() != current.strip():
            self._conf_path.parent.mkdir(parents=True, exist_ok=True)
            write_file(self._conf_path, new_content, "root", 0o644)

    def _write_wrapper_atomic(self) -> None:
        """Atomically write and validate tlog-wrapper.

        Raises:
            TlogServiceError: if the wrapper fails sh -n, is non-executable after write,
                              or tlog-rec-session binary is absent.

        """
        if not self._tlog_bin.exists():
            raise TlogServiceError(f"{TLOG_BIN} not found; is tlog installed?")

        new_wrapper = render_jinja2_template({}, TLOG_WRAPPER_TEMPLATE, TLOG_TEMPLATE_FILE_PATH)
        current = (
            self._wrapper_path.read_text(encoding="utf-8") if self._wrapper_path.exists() else ""
        )
        if new_wrapper == current:
            return

        # Validate content before writing (syntax check)
        result = subprocess.run(
            ["sh", "-n"],
            input=new_wrapper,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise TlogServiceError(f"Wrapper syntax error: {result.stderr.strip()}")

        write_file_with_group(self._wrapper_path, new_wrapper, "root", "root", 0o755)

    def _write_logrotate(self) -> None:
        """Write /etc/logrotate.d/tlog if content changed (chattr +a aware)."""
        current = (
            self._logrotate_path.read_text(encoding="utf-8")
            if self._logrotate_path.exists()
            else ""
        )
        if _TLOG_LOGROTATE_CONTENT != current:
            write_file(self._logrotate_path, _TLOG_LOGROTATE_CONTENT, "root", 0o644)

    def _write_sshd_snippet(self, groups: str) -> None:
        """Write sshd drop-in, run sshd -t, reload. Reverts snippet on sshd -t failure (C5).

        Raises:
            TlogServiceReloadError: sshd -t failed (snippet reverted) or reload failed.

        """
        new_snippet = render_jinja2_template(
            {"session_recording_groups": groups},
            TLOG_SSHD_CONF_TEMPLATE,
            TLOG_TEMPLATE_FILE_PATH,
        )
        current = (
            self._snippet_path.read_text(encoding="utf-8") if self._snippet_path.exists() else ""
        )
        if new_snippet == current:
            return

        self._snippet_path.parent.mkdir(parents=True, exist_ok=True)
        write_file(self._snippet_path, new_snippet, "root", 0o644)
        self.validate_sshd()
        self.reload_sshd()

    def validate_sshd(self) -> None:
        """Run sshd -t; revert snippet and raise on failure (C5).

        Raises:
            TlogServiceReloadError: sshd config is invalid (snippet removed).

        """
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.error("sshd -t failed: %s", result.stderr.strip())
            self._snippet_path.unlink(missing_ok=True)
            raise TlogServiceReloadError(
                f"sshd config invalid after writing snippet; reverted. "
                f"sshd -t output: {result.stderr.strip()}"
            )

    def reload_sshd(self) -> None:
        """Reload sshd without dropping live sessions.

        Raises:
            TlogServiceReloadError: reload failed.

        """
        try:
            systemd.service_reload(self.sshd_service)
        except systemd.SystemdError as exc:
            raise TlogServiceReloadError(f"Failed to reload {self.sshd_service}.") from exc
