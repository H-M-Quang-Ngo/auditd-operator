# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Common of globals variables to the charm."""

# Auditd rules
AUDIT_RULE_PATH = "./src/audit_rules"

# Template files
TEMPLATE_FILE_PATH = "./src/auditd_templates"
AUDITD_CONFIG_TEMPLATE = "auditd.conf.j2"

# Common constants
AUDITD_MIN_NUM_LOGS = 0
AUDITD_MAX_NUM_LOGS = 999

# Session recording group validation
# Conservative charset: lowercase, digits, underscore, hyphen. Matches standard Unix group names.
GROUP_NAME_PATTERN = r"^[a-z_][a-z0-9_-]*$"
# Groups that match far more users than intended via sshd Match Group OR-semantics.
DANGEROUS_GROUPS = frozenset({"root", "sudo", "adm", "users", "nogroup", "daemon"})

# tlog paths
TLOG_TEMPLATE_FILE_PATH = "./src/tlog_templates"
TLOG_SSHD_CONF_TEMPLATE = "tlog_sshd.conf.j2"
TLOG_REC_SESSION_CONF_TEMPLATE = "tlog_rec_session.conf.j2"
TLOG_WRAPPER_TEMPLATE = "tlog_wrapper.sh.j2"

TLOG_LOG_DIR = "/var/log/tlog"
TLOG_LOG_FILE = "/var/log/tlog/sessions.log"
TLOG_CONF_FILE = "/etc/tlog/tlog-rec-session.conf"
TLOG_WRAPPER_FILE = "/usr/local/bin/tlog-wrapper"
TLOG_SSHD_SNIPPET = "/etc/ssh/sshd_config.d/99-tlog-recording.conf"
TLOG_BIN = "/usr/bin/tlog-rec-session"
TLOG_LOGROTATE_FILE = "/etc/logrotate.d/tlog"

# Privileged-recorder setup for tlog-rec-session.
# Without setuid the recorded user runs fully unprivileged
# and cannot write the tamper-protected (tlog:adm 0640) log,
# so recording fails with EACCES.
TLOG_SYSTEM_USER = "tlog"
TLOG_SYSTEM_GROUP = "tlog"
TLOG_BIN_MODE = 0o6755

# Ownership for /var/log/tlog/ and sessions.log
TLOG_LOG_DIR_OWNER = "tlog"
TLOG_LOG_DIR_GROUP = "tlog"
TLOG_LOG_DIR_MODE = 0o2750  # setgid dir: owner=tlog, group=tlog, no world access
TLOG_LOG_FILE_OWNER = "tlog"
TLOG_LOG_FILE_GROUP = "adm"  # Grafana Agent/Opentelemetry Collector reads via group adm
TLOG_LOG_FILE_MODE = 0o640
