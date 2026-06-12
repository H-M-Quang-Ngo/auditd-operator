from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from tlog_workload import (
    _TLOG_LOGROTATE_CONTENT,
    TlogService,
    TlogServiceError,
    TlogServiceReloadError,
)


@pytest.fixture()
def svc():
    return TlogService()


def _mock_file(content: str = "") -> MagicMock:
    m = MagicMock(spec=Path)
    m.exists.return_value = bool(content)
    m.read_text.return_value = content
    return m


@patch("tlog_workload.apt.add_package")
def test_install_success(mock_add, svc):
    svc.install()
    mock_add.assert_called_once_with(package_names="tlog")


@patch(
    "tlog_workload.apt.add_package",
    side_effect=apt.PackageError("Failed to install packages: tlog"),
)
def test_install_failure_raises_with_universe_hint(mock_add, svc):
    with pytest.raises(TlogServiceError, match="universe"):
        svc.install()


@patch("tlog_workload.apt.DebianPackage.from_installed_package")
def test_is_installed_true(_, svc):
    assert svc.is_installed() is True


@patch(
    "tlog_workload.apt.DebianPackage.from_installed_package",
    side_effect=apt.PackageNotFoundError,
)
def test_is_installed_false(_, svc):
    assert svc.is_installed() is False


@patch("tlog_workload.apt.remove_package")
@patch("tlog_workload.apt.DebianPackage.from_installed_package")
def test_remove_when_installed(mock_installed, mock_remove, svc):
    svc.remove()
    mock_remove.assert_called_once_with(package_names="tlog")


@patch(
    "tlog_workload.apt.DebianPackage.from_installed_package",
    side_effect=apt.PackageNotFoundError,
)
@patch("tlog_workload.apt.remove_package")
def test_remove_when_not_installed(mock_remove, _, svc):
    svc.remove()
    mock_remove.assert_not_called()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_empty_no_snippet_no_reload(mock_reload, mock_reload_rules, svc, tmp_path):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    svc._audit_rules_path = tmp_path / "tlog.rules"
    svc.configure("")
    mock_reload.assert_not_called()
    mock_reload_rules.assert_not_called()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_empty_removes_snippet_and_reloads(mock_reload, _reload_rules, svc, tmp_path):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("old snippet")
    svc._snippet_path = snippet
    svc._audit_rules_path = tmp_path / "tlog.rules"
    svc.configure("")
    assert not snippet.exists()
    mock_reload.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_empty_removes_audit_rules_and_reloads(
    mock_reload_sshd, mock_reload_rules, svc, tmp_path
):
    """Disabling removes the tamper rules installed by the enable path."""
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    rules = tmp_path / "tlog.rules"
    rules.write_text("-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n")
    svc._audit_rules_path = rules
    svc.configure("")
    assert not rules.exists()
    mock_reload_rules.assert_called_once()
    mock_reload_sshd.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_enable_ordering(
    mock_installed,
    mock_ensure,
    mock_conf,
    mock_wrapper,
    mock_validate,
    mock_reload,
    mock_priv,
    svc,
    tmp_path,
):
    """Snippet must be written last, sshd -t and reload follow snippet write."""
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"

    with (
        patch("tlog_workload.render_jinja2_template", return_value="new-snippet"),
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_logrotate") as mock_logrotate,
        patch.object(TlogService, "_ensure_audit_rules") as mock_rules,
    ):
        svc.configure("warthogs")

    call_order = [mock_ensure, mock_conf, mock_wrapper, mock_logrotate, mock_rules]
    for m in call_order:
        m.assert_called_once()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_snippet_not_written_when_wrapper_fails(
    _installed, _ensure, _conf, mock_wrapper, mock_validate, mock_reload, _priv, svc, tmp_path
):
    """If wrapper validation fails, snippet must not be written."""
    mock_wrapper.side_effect = TlogServiceError("bad wrapper")
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet

    with pytest.raises(TlogServiceError):
        svc.configure("warthogs")

    assert not snippet.exists()
    mock_validate.assert_not_called()
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_sshd_t_failure_reverts_snippet(
    _installed, _ensure, _conf, _wrapper, _logrotate, _rules, mock_reload, _priv, svc, tmp_path
):
    """Sshd -t failure with no previous snippet must remove the written snippet."""
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet

    with (
        patch(
            "tlog_workload.subprocess.run",
            return_value=MagicMock(returncode=1, stderr="bad config"),
        ),
        patch("tlog_workload.render_jinja2_template", return_value="new-snippet"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure("warthogs")

    assert not snippet.exists(), "snippet must be reverted on sshd -t failure"
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_sshd_t_failure_restores_previous_snippet(
    _installed, _ensure, _conf, _wrapper, _logrotate, _rules, mock_reload, _priv, svc, tmp_path
):
    """A failed validation must restore the previous working snippet, not delete it."""
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("Match Group oldgroup\n")
    svc._snippet_path = snippet

    with (
        patch(
            "tlog_workload.subprocess.run",
            return_value=MagicMock(returncode=1, stderr="bad config"),
        ),
        patch("tlog_workload.render_jinja2_template", return_value="Match Group newgroup\n"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure("newgroup")

    assert snippet.read_text() == "Match Group oldgroup\n"
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(
    TlogService, "reload_sshd", side_effect=TlogServiceReloadError("Failed to reload ssh.")
)
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_reload_failure_restores_previous_snippet(
    _installed,
    _ensure,
    _conf,
    _wrapper,
    _logrotate,
    _rules,
    _validate,
    _reload,
    _priv,
    svc,
    tmp_path,
):
    """A failed reload must restore the previous snippet.

    The next reconcile then sees a content difference and retries the reload
    instead of skipping it as unchanged.
    """
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("Match Group oldgroup\n")
    svc._snippet_path = snippet

    with (
        patch("tlog_workload.render_jinja2_template", return_value="Match Group newgroup\n"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure("newgroup")

    assert snippet.read_text() == "Match Group oldgroup\n"


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_no_reload_when_snippet_unchanged(
    _installed, mock_validate, mock_reload, _priv, svc, tmp_path
):
    """No sshd reload if snippet content did not change."""
    groups = "warthogs"
    expected_snippet = "Match Group warthogs\n    ForceCommand /usr/local/bin/tlog-wrapper\n"
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text(expected_snippet)
    svc._snippet_path = snippet
    svc._conf_path = tmp_path / "tlog-rec-session.conf"
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"

    with (
        patch("tlog_workload.render_jinja2_template") as mock_render,
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_wrapper_atomic"),
        patch.object(TlogService, "ensure_log_dir"),
        patch.object(TlogService, "_write_tlog_conf"),
        patch.object(TlogService, "_write_logrotate"),
        patch.object(TlogService, "_ensure_audit_rules"),
    ):
        mock_render.return_value = expected_snippet
        svc.configure(groups)

    mock_reload.assert_not_called()
    mock_validate.assert_not_called()


@patch("tlog_workload.subprocess.run", return_value=MagicMock(returncode=0, stderr=""))
def test_validate_sshd_success(mock_run, svc, tmp_path):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    svc.validate_sshd()
    mock_run.assert_called_once()


def test_validate_sshd_failure_raises_and_keeps_snippet(svc, tmp_path):
    """validate_sshd only validates; reverting is the caller's responsibility."""
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("pending config")
    svc._snippet_path = snippet

    with patch(
        "tlog_workload.subprocess.run",
        return_value=MagicMock(returncode=1, stderr="bad config error"),
    ):
        with pytest.raises(TlogServiceReloadError, match="validation failed"):
            svc.validate_sshd()

    assert snippet.read_text() == "pending config"


@patch("tlog_workload.systemd.service_reload")
def test_reload_sshd_success(mock_reload, svc):
    svc.reload_sshd()
    mock_reload.assert_called_once_with("ssh")


@patch("tlog_workload.systemd.service_reload", side_effect=systemd.SystemdError)
def test_reload_sshd_failure(_, svc):
    with pytest.raises(TlogServiceReloadError):
        svc.reload_sshd()


@patch("tlog_workload.write_file")
def test_write_logrotate_writes_when_absent(mock_write, svc, tmp_path):
    svc._logrotate_path = tmp_path / "tlog"
    svc._write_logrotate()
    mock_write.assert_called_once()


@patch("tlog_workload.write_file")
def test_write_logrotate_no_write_when_unchanged(mock_write, svc, tmp_path):
    logrotate = tmp_path / "tlog"
    logrotate.write_text(_TLOG_LOGROTATE_CONTENT)
    svc._logrotate_path = logrotate
    svc._write_logrotate()
    mock_write.assert_not_called()


@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.make_dir")
def test_ensure_log_dir_creates_file_when_absent(
    mock_make_dir, mock_write, mock_attr, svc, tmp_path
):
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"
    svc.ensure_log_dir()
    mock_make_dir.assert_called_once()
    mock_write.assert_called_once()
    mock_attr.assert_called_once()


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown")
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=4))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=999))
@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.make_dir")
def test_ensure_log_dir_heals_existing_file_without_rewrite(
    mock_make_dir, mock_write, mock_attr, mock_pwd, mock_grp, mock_chown, mock_chmod, svc, tmp_path
):
    """An existing file gets ownership/mode healed but its content is never touched."""
    log_dir = tmp_path / "tlog"
    log_dir.mkdir()
    log_file = log_dir / "sessions.log"
    log_file.write_text("existing recording data")
    svc._log_dir = log_dir
    svc._log_file = log_file
    svc.ensure_log_dir()
    mock_write.assert_not_called()
    mock_pwd.assert_called_once_with("_tlog")
    mock_grp.assert_called_once_with("adm")
    mock_chown.assert_called_once_with(log_file, 999, 4)
    mock_chmod.assert_called_once_with(log_file, 0o640)
    assert log_file.read_text() == "existing recording data"
    mock_attr.assert_called_once()


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=0, stderr=""),
)
def test_ensure_append_only_sets_attr(mock_run, svc, tmp_path):
    svc._log_file = tmp_path / "sessions.log"
    svc._ensure_append_only()
    mock_run.assert_called_once_with(
        ["chattr", "+a", str(svc._log_file)],
        capture_output=True,
        text=True,
        check=False,
    )


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="Operation not supported"),
)
def test_ensure_append_only_warns_and_does_not_raise(mock_run, svc, tmp_path):
    """An unsupported filesystem must not break recording."""
    svc._log_file = tmp_path / "sessions.log"
    svc._ensure_append_only()  # no exception


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "_write_sshd_snippet")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "ensure_log_dir")
@patch.object(TlogService, "install")
@patch.object(TlogService, "is_installed", return_value=False)
def test_configure_installs_when_not_installed(
    _installed, mock_install, _ensure, _conf, _wrapper, _logrotate, _rules, _snippet, _priv, svc
):
    svc.configure("warthogs")
    mock_install.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch("tlog_workload.write_file")
def test_ensure_audit_rules_writes_and_reloads_on_change(mock_write, mock_reload, svc, tmp_path):
    source = tmp_path / "tlog.rules"
    source.write_text("-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n")
    svc._audit_rules_source = source
    svc._audit_rules_path = tmp_path / "dest-tlog.rules"
    svc._ensure_audit_rules()
    mock_write.assert_called_once()
    mock_reload.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch("tlog_workload.write_file")
def test_ensure_audit_rules_no_reload_when_unchanged(mock_write, mock_reload, svc, tmp_path):
    content = "-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n"
    source = tmp_path / "tlog.rules"
    source.write_text(content)
    dest = tmp_path / "dest-tlog.rules"
    dest.write_text(content)
    svc._audit_rules_source = source
    svc._audit_rules_path = dest
    svc._ensure_audit_rules()
    mock_write.assert_not_called()
    mock_reload.assert_not_called()


@patch("tlog_workload.subprocess.run", return_value=MagicMock(returncode=0, stderr=""))
def test_reload_audit_rules_invokes_augenrules(mock_run, svc):
    svc._reload_audit_rules()
    mock_run.assert_called_once_with(
        ["augenrules", "--load"],
        capture_output=True,
        text=True,
        check=False,
    )


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="augenrules failure"),
)
def test_reload_audit_rules_failure_does_not_raise(mock_run, svc):
    """Recording must keep working when rule loading fails; failure is logged."""
    svc._reload_audit_rules()


@patch("tlog_workload.write_file")
@patch("tlog_workload.render_jinja2_template", return_value="new-conf")
def test_write_tlog_conf_writes_when_absent(mock_render, mock_write, svc, tmp_path):
    svc._conf_path = tmp_path / "tlog-rec-session.conf"
    svc._log_file = tmp_path / "sessions.log"
    svc._write_tlog_conf()
    mock_write.assert_called_once()


@patch("tlog_workload.write_file")
@patch("tlog_workload.render_jinja2_template", return_value="same-conf")
def test_write_tlog_conf_no_write_when_unchanged(mock_render, mock_write, svc, tmp_path):
    conf = tmp_path / "tlog-rec-session.conf"
    conf.write_text("same-conf")
    svc._conf_path = conf
    svc._log_file = tmp_path / "sessions.log"
    svc._write_tlog_conf()
    mock_write.assert_not_called()


def test_write_wrapper_atomic_raises_when_tlog_bin_absent(svc, tmp_path):
    svc._tlog_bin = tmp_path / "no-tlog-rec-session"
    with pytest.raises(TlogServiceError, match="not found"):
        svc._write_wrapper_atomic()


@patch("tlog_workload.write_file_with_group")
@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=0, stdout=""),
)
@patch("tlog_workload.render_jinja2_template", return_value="new-wrapper")
def test_write_wrapper_atomic_writes_on_change(mock_render, mock_run, mock_write, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    svc._write_wrapper_atomic()
    mock_write.assert_called_once()


@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.render_jinja2_template", return_value="same-wrapper")
def test_write_wrapper_atomic_no_write_when_unchanged(mock_render, mock_write, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    wrapper = tmp_path / "tlog-wrapper"
    wrapper.write_text("same-wrapper")
    svc._wrapper_path = wrapper
    svc._write_wrapper_atomic()
    mock_write.assert_not_called()


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="syntax error"),
)
@patch("tlog_workload.render_jinja2_template", return_value="bad-wrapper")
def test_write_wrapper_atomic_raises_on_syntax_error(mock_render, mock_run, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    with pytest.raises(TlogServiceError, match="Wrapper syntax error"):
        svc._write_wrapper_atomic()


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown")
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=900))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=900))
def test_ensure_privileged_recorder_sets_setuid(mock_pwd, mock_grp, mock_chown, mock_chmod, svc):
    """Binary is chowned to the package _tlog principal then set mode 6755."""
    svc._tlog_bin = Path("/usr/bin/tlog-rec-session")
    svc._ensure_privileged_recorder()
    mock_pwd.assert_called_once_with("_tlog")
    mock_grp.assert_called_once_with("_tlog")
    mock_chown.assert_called_once_with(svc._tlog_bin, 900, 900)
    mock_chmod.assert_called_once_with(svc._tlog_bin, 0o6755)


@patch("tlog_workload.pwd.getpwnam", side_effect=KeyError("_tlog"))
def test_ensure_privileged_recorder_raises_when_principal_missing(mock_pwd, svc):
    """A missing _tlog principal raises, not crash."""
    with pytest.raises(TlogServiceError, match="tlog installation"):
        svc._ensure_privileged_recorder()
