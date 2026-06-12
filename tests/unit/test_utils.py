from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest

import utils


def test_read_file(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("hello", encoding="utf-8")
    assert utils.read_file(file) == "hello"


@patch("utils.os.chmod")
@patch("utils.pwd.getpwnam")
@patch("utils.os.chown")
def test_write_file(mock_chown, mock_getpwnam, mock_chmod, tmp_path):
    file = tmp_path / "test.txt"
    mock_getpwnam.return_value = MagicMock(pw_uid=1000, pw_gid=1000)
    utils.write_file(file, "data", "root", 0o600)
    assert file.read_text(encoding="utf-8") == "data"
    mock_chmod.assert_called_once()
    mock_getpwnam.assert_called_once_with("root")
    mock_chown.assert_called_once()


@patch("utils.Environment")
def test_render_jinja2_template(mock_env):
    mock_template = MagicMock()
    mock_template.render.return_value = "rendered"
    mock_env.return_value.get_template.return_value = mock_template
    result = utils.render_jinja2_template({"foo": "bar"}, "template", "/path")
    assert result == "rendered"
    mock_env.return_value.get_template.assert_called_once_with("template")
    mock_template.render.assert_called_once_with({"foo": "bar"})


@patch("utils.subprocess.run", return_value=MagicMock(returncode=0, stdout="qemu\n", stderr=""))
def test_get_machine_virt_type_success(mock_run):
    assert utils.get_machine_virt_type() == "qemu"
    mock_run.assert_called_once_with(
        ["systemd-detect-virt"], capture_output=True, text=True, check=False
    )


@patch("utils.subprocess.run", return_value=MagicMock(returncode=1, stdout="none\n", stderr=""))
def test_get_machine_virt_type_bare_metal(mock_run):
    assert utils.get_machine_virt_type() == "none"
    mock_run.assert_called_once_with(
        ["systemd-detect-virt"], capture_output=True, text=True, check=False
    )


@patch("utils.subprocess.run", return_value=MagicMock(returncode=2, stdout="", stderr="error"))
def test_get_machine_virt_type_failure(_):
    with pytest.raises(CalledProcessError):
        utils.get_machine_virt_type()


@patch("utils.os.chmod")
@patch("utils.os.chown")
@patch("utils.grp.getgrnam")
@patch("utils.pwd.getpwnam")
def test_write_file_with_group(mock_pw, mock_gr, mock_chown, mock_chmod, tmp_path):
    mock_pw.return_value = MagicMock(pw_uid=1001)
    mock_gr.return_value = MagicMock(gr_gid=1002)
    path = tmp_path / "file.txt"
    utils.write_file_with_group(path, "content", "tlog", "adm", 0o640)
    assert path.exists()
    assert path.read_text(encoding="utf-8") == "content"
    mock_chmod.assert_called_once()
    mock_chown.assert_called_once()


@patch("utils.os.chmod")
@patch("utils.os.chown")
@patch("utils.grp.getgrnam")
@patch("utils.pwd.getpwnam")
def test_write_file_with_group_cleans_up_on_failure(
    mock_pw, mock_gr, mock_chown, mock_chmod, tmp_path
):
    mock_pw.return_value = MagicMock(pw_uid=1001)
    mock_gr.return_value = MagicMock(gr_gid=1002)
    mock_chown.side_effect = PermissionError("no permission")
    path = tmp_path / "file.txt"
    with pytest.raises(PermissionError):
        utils.write_file_with_group(path, "content", "tlog", "adm", 0o640)
    assert not path.exists()


@patch("utils.os.unlink", side_effect=OSError("cannot unlink"))
@patch("utils.os.chmod")
@patch("utils.os.chown")
@patch("utils.grp.getgrnam")
@patch("utils.pwd.getpwnam")
def test_write_file_with_group_unlink_failure_suppressed(
    mock_pw, mock_gr, mock_chown, mock_chmod, mock_unlink, tmp_path
):
    """OSError during temp-file cleanup is suppressed; original error re-raised."""
    mock_pw.return_value = MagicMock(pw_uid=1001)
    mock_gr.return_value = MagicMock(gr_gid=1002)
    mock_chown.side_effect = PermissionError("no permission")
    path = tmp_path / "file.txt"
    with pytest.raises(PermissionError):
        utils.write_file_with_group(path, "content", "tlog", "adm", 0o640)


@patch("utils.os.chmod")
@patch("utils.os.chown")
@patch("utils.grp.getgrnam")
@patch("utils.pwd.getpwnam")
def test_make_dir(mock_pw, mock_gr, mock_chown, mock_chmod, tmp_path):
    mock_pw.return_value = MagicMock(pw_uid=1001)
    mock_gr.return_value = MagicMock(gr_gid=1002)
    target = tmp_path / "subdir"
    utils.make_dir(target, "tlog", "tlog", 0o2750)
    assert target.exists()
    mock_chown.assert_called_once_with(target, uid=1001, gid=1002)
    mock_chmod.assert_called_once_with(target, 0o2750)
