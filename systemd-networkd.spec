#global gitcommit 10e465b5321bd53c1fc59ffab27e724535c6bc0f
%{?gitcommit:%global gitcommitshort %(c=%{gitcommit}; echo ${c:0:7})}

# We ship a .pc file but don't want to have a dep on pkg-config. We
# strip the automatically generated dep here and instead co-own the
# directory.
%global __requires_exclude pkg-config

%global pkgdir %{_prefix}/lib/systemd
%global system_unit_dir %{pkgdir}/system
%global user_unit_dir %{pkgdir}/user

Name:           systemd-networkd
Url:            http://www.freedesktop.org/wiki/Software/systemd
Version:        239
Release:        18%{?dist}_1.1
# For a breakdown of the licensing, see README
License:        LGPLv2+ and MIT and GPLv2+
Summary:        System and Service Manager
Requires:       systemd = %{version}-%{release}

# download tarballs with "spectool -g systemd.spec"
%if %{defined gitcommit}
Source0:        https://github.com/systemd/systemd-stable/archive/%{?gitcommit}.tar.gz#/systemd-%{gitcommitshort}.tar.gz
%else
Source0:        https://github.com/systemd/systemd/archive/v%{version}.tar.gz#/systemd-%{version}.tar.gz
%endif
# This file must be available before %%prep.
# It is generated during systemd build and can be found in src/core/.
Source1:        triggers.systemd
Source2:        split-files.py
Source3:        purge-nobody-user

# Prevent accidental removal of the systemd package
Source4:        yum-protect-systemd.conf

Source5:        inittab
Source6:        sysctl.conf.README
Source7:        systemd-journal-remote.xml
Source8:        systemd-journal-gatewayd.xml
Source9:        20-yama-ptrace.conf
Source10:       systemd-udev-trigger-no-reload.conf
Source11:       20-grubby.install
Source12:       systemd-user
Source13:       rc.local

%if 0
GIT_DIR=../../src/systemd/.git git format-patch-ab --no-signature -M -N v235..v235-stable
i=1; for j in 00*patch; do printf "Patch%04d:      %s\n" $i $j; i=$((i+1));done|xclip
GIT_DIR=../../src/systemd/.git git diffab -M v233..master@{2017-06-15} -- hwdb/[67]* hwdb/parse_hwdb.py > hwdb.patch
%endif

# RHEL-specific
Patch0001: 0001-build-sys-Detect-whether-struct-statx-is-defined-in-.patch
Patch0002: 0002-logind-set-RemoveIPC-to-false-by-default.patch
Patch0003: 0003-pid1-bump-DefaultTasksMax-to-80-of-the-kernel-pid.ma.patch
Patch0004: 0004-Avoid-tmp-being-mounted-as-tmpfs-without-the-user-s-.patch
Patch0005: 0005-pid1-bump-maximum-number-of-process-in-user-slice-to.patch
Patch0006: 0006-rules-automatically-online-hot-plugged-CPUs.patch
Patch0007: 0007-rules-add-rule-for-naming-Dell-iDRAC-USB-Virtual-NIC.patch
Patch0008: 0008-rules-enable-memory-hotplug.patch
Patch0009: 0009-rules-reload-sysctl-settings-when-the-bridge-module-.patch
Patch0010: 0010-rules-load-sg-module.patch
Patch0011: 0011-rules-prandom-character-device-node-permissions.patch
Patch0012: 0012-rules-load-sg-driver-also-when-scsi_target-appears-4.patch
Patch0013: 0013-rules-don-t-hoplug-memory-on-s390x.patch
Patch0014: 0014-rules-disable-auto-online-of-hot-plugged-memory-on-I.patch
Patch0015: 0015-rules-introduce-old-style-by-path-symlinks-for-FCP-b.patch
Patch0016: 0016-Revert-udev-remove-WAIT_FOR-key.patch
Patch0017: 0017-net_setup_link-allow-renaming-interfaces-that-were-r.patch
Patch0018: 0018-units-drop-DynamicUser-yes-from-systemd-resolved.ser.patch
Patch0019: 0019-journal-remove-journal-audit-socket.patch
Patch0020: 0020-bus-move-BUS_DONT_DESTROY-calls-after-asserts.patch
Patch0021: 0021-random-seed-raise-POOL_SIZE_MIN-constant-to-1024.patch
Patch0022: 0022-cryptsetup-add-support-for-sector-size-option-9936.patch
Patch0023: 0023-cryptsetup-do-not-define-arg_sector_size-if-libgcryp.patch
Patch0024: 0024-units-don-t-enable-per-service-IP-firewall-by-defaul.patch
Patch0025: 0025-bus-message-do-not-crash-on-message-with-a-string-of.patch
Patch0026: 0026-Introduce-free_and_strndup-and-use-it-in-bus-message.patch
Patch0027: 0027-tests-backport-test_setup_logging.patch
Patch0028: 0028-journal-change-support-URL-shown-in-the-catalog-entr.patch
Patch0029: 0029-resolved-create-etc-resolv.conf-symlink-at-runtime.patch
Patch0030: 0030-dissect-image-use-right-comparison-function.patch
Patch0031: 0031-login-avoid-leak-of-name-returned-by-uid_to_name.patch
Patch0032: 0032-firewall-util-add-an-assert-that-we-re-not-overwriti.patch
Patch0033: 0033-journal-file-avoid-calling-ftruncate-with-invalid-fd.patch
Patch0034: 0034-dhcp6-make-sure-we-have-enough-space-for-the-DHCP6-o.patch
Patch0035: 0035-core-rename-queued_message-pending_reload_message.patch
Patch0036: 0036-core-when-we-can-t-send-the-pending-reload-message-s.patch
Patch0037: 0037-core-make-sure-we-don-t-throttle-change-signal-gener.patch
Patch0038: 0038-proc-cmdline-introduce-PROC_CMDLINE_RD_STRICT.patch
Patch0039: 0039-debug-generator-introduce-rd.-version-of-all-options.patch
Patch0040: 0040-chown-recursive-let-s-rework-the-recursive-logic-to-.patch
Patch0041: 0041-chown-recursive-also-drop-ACLs-when-recursively-chow.patch
Patch0042: 0042-chown-recursive-TAKE_FD-is-your-friend.patch
Patch0043: 0043-test-add-test-case-for-recursive-chown-ing.patch
Patch0044: 0044-Revert-sysctl.d-request-ECN-on-both-in-and-outgoing-.patch
Patch0045: 0045-detect-virt-do-not-try-to-read-all-of-proc-cpuinfo.patch
Patch0046: 0046-sd-bus-unify-three-code-paths-which-free-struct-bus_.patch
Patch0047: 0047-sd-bus-properly-initialize-containers.patch
Patch0048: 0048-cryptsetup-generator-introduce-basic-keydev-support.patch
Patch0049: 0049-cryptsetup-don-t-use-m-if-there-s-no-error-to-show.patch
Patch0050: 0050-cryptsetup-generator-don-t-return-error-if-target-di.patch
Patch0051: 0051-cryptsetup-generator-allow-whitespace-characters-in-.patch
Patch0052: 0052-rules-watch-metadata-changes-on-DASD-devices.patch
Patch0053: 0053-sysctl.d-switch-net.ipv4.conf.all.rp_filter-from-1-t.patch
Patch0054: 0054-tests-explicitly-enable-user-namespaces-for-TEST-13-.patch
Patch0055: 0055-nspawn-beef-up-netns-checking-a-bit-for-compat-with-.patch
Patch0056: 0056-test-Drop-SKIP_INITRD-for-QEMU-based-tests.patch
Patch0057: 0057-meson-rename-Ddebug-to-Ddebug-extra.patch
Patch0058: 0058-meson-check-whether-gnutls-supports-TCP-fast-open.patch
Patch0059: 0059-unit-don-t-add-Requires-for-tmp.mount.patch
Patch0060: 0060-tests-drop-the-precondition-check-for-inherited-flag.patch
Patch0061: 0061-core-when-deserializing-state-always-use-read_line-L.patch
Patch0062: 0062-core-enforce-a-limit-on-STATUS-texts-recvd-from-serv.patch
Patch0063: 0063-travis-enable-Travis-CI-on-CentOS-7.patch
Patch0064: 0064-travis-RHEL8-support.patch
Patch0065: 0065-travis-drop-the-SELinux-Fedora-workaround.patch
Patch0066: 0066-travis-fix-syntax-error-in-.travis.yml.patch
Patch0067: 0067-travis-reboot-the-container-before-running-tests.patch
Patch0068: 0068-coredump-remove-duplicate-MESSAGE-prefix-from-messag.patch
Patch0069: 0069-journald-remove-unnecessary.patch
Patch0070: 0070-journald-do-not-store-the-iovec-entry-for-process-co.patch
Patch0071: 0071-basic-process-util-limit-command-line-lengths-to-_SC.patch
Patch0072: 0072-coredump-fix-message-when-we-fail-to-save-a-journald.patch
Patch0073: 0073-procfs-util-expose-functionality-to-query-total-memo.patch
Patch0074: 0074-basic-prioq-add-prioq_peek_item.patch
Patch0075: 0075-journal-limit-the-number-of-entries-in-the-cache-bas.patch
Patch0076: 0076-journald-periodically-drop-cache-for-all-dead-PIDs.patch
Patch0077: 0077-process-util-don-t-use-overly-large-buffer-to-store-.patch
Patch0078: 0078-Revert-sysctl.d-switch-net.ipv4.conf.all.rp_filter-f.patch
Patch0079: 0079-journal-fix-syslog_parse_identifier.patch
Patch0080: 0080-journald-set-a-limit-on-the-number-of-fields-1k.patch
Patch0081: 0081-journald-when-processing-a-native-message-bail-more-.patch
Patch0082: 0082-journald-lower-the-maximum-entry-size-limit-to-for-n.patch
Patch0083: 0083-httpd-use-a-cleanup-function-to-call-MHD_destroy_res.patch
Patch0084: 0084-journal-remote-verify-entry-length-from-header.patch
Patch0085: 0085-journal-remote-set-a-limit-on-the-number-of-fields-i.patch
Patch0086: 0086-journald-correctly-attribute-log-messages-also-with-.patch
Patch0087: 0087-test-replace-echo-with-socat.patch
Patch0088: 0088-test-network-ignore-tunnel-devices-automatically-add.patch
Patch0089: 0089-rules-add-elevator-kernel-command-line-parameter.patch
Patch0090: 0090-rule-syntax-check-allow-PROGRAM-as-an-assignment.patch
Patch0091: 0091-rules-implement-new-memory-hotplug-policy.patch
Patch0092: 0092-LGTM-make-LGTM.com-use-meson-from-pip.patch
Patch0093: 0093-lgtm-use-python3.patch
Patch0094: 0094-tools-use-print-function-in-Python-3-code.patch
Patch0095: 0095-lgtm-add-a-custom-query-for-catching-the-use-of-fget.patch
Patch0096: 0096-lgtm-drop-redundant-newlines.patch
Patch0097: 0097-rules-add-the-rule-that-adds-elevator-kernel-command.patch
Patch0098: 0098-test-add-TEST-24-UNIT-TESTS-running-all-basic-tests-.patch
Patch0099: 0099-tests-create-the-asan-wrapper-automatically-if-syste.patch
Patch0100: 0100-tests-add-a-wrapper-for-when-systemd-is-built-with-A.patch
Patch0101: 0101-tests-redirect-ASAN-reports-on-journald-to-a-file.patch
Patch0102: 0102-tests-use-the-asan-wrapper-to-boot-a-VM-container-if.patch
Patch0103: 0103-tests-allow-passing-additional-arguments-to-nspawn-v.patch
Patch0104: 0104-tests-also-run-TEST-01-BASIC-in-an-unprivileged-cont.patch
Patch0105: 0105-test-don-t-overwrite-TESTDIR-if-already-set.patch
Patch0106: 0106-bus-socket-Fix-line_begins-to-accept-word-matching-f.patch
Patch0107: 0107-Refuse-dbus-message-paths-longer-than-BUS_PATH_SIZE_.patch
Patch0108: 0108-Allocate-temporary-strings-to-hold-dbus-paths-on-the.patch
Patch0109: 0109-sd-bus-if-we-receive-an-invalid-dbus-message-ignore-.patch
Patch0110: 0110-meson-drop-misplaced-Wl-undefined-argument.patch
Patch0111: 0111-Revert-core-one-step-back-again-for-nspawn-we-actual.patch
Patch0112: 0112-tree-wide-shorten-error-logging-a-bit.patch
Patch0113: 0113-nspawn-simplify-machine-terminate-bus-call.patch
Patch0114: 0114-nspawn-merge-two-variable-declaration-lines.patch
Patch0115: 0115-nspawn-rework-how-we-allocate-kill-scopes.patch
Patch0116: 0116-unit-enqueue-cgroup-empty-check-event-if-the-last-re.patch
Patch0117: 0117-Revert-journal-remove-journal-audit-socket.patch
Patch0118: 0118-journal-don-t-enable-systemd-journald-audit.socket-b.patch
Patch0119: 0119-logs-show-use-grey-color-for-de-emphasizing-journal-.patch
Patch0120: 0120-units-add-Install-section-to-tmp.mount.patch
Patch0121: 0121-nss-do-not-modify-errno-when-NSS_STATUS_NOTFOUND-or-.patch
Patch0122: 0122-util.h-add-new-UNPROTECT_ERRNO-macro.patch
Patch0123: 0123-nss-unportect-errno-before-writing-to-NSS-errnop.patch
Patch0124: 0124-seccomp-reduce-logging-about-failure-to-add-syscall-.patch
Patch0125: 0125-format-table-when-duplicating-a-cell-also-copy-the-c.patch
Patch0126: 0126-format-table-optionally-make-specific-cells-clickabl.patch
Patch0127: 0127-format-table-before-outputting-a-color-check-if-colo.patch
Patch0128: 0128-format-table-add-option-to-store-format-percent-and-.patch
Patch0129: 0129-format-table-optionally-allow-reversing-the-sort-ord.patch
Patch0130: 0130-format-table-add-table_update-to-update-existing-ent.patch
Patch0131: 0131-format-table-add-an-API-for-getting-the-cell-at-a-sp.patch
Patch0132: 0132-format-table-always-underline-header-line.patch
Patch0133: 0133-format-table-add-calls-to-query-the-data-in-a-specif.patch
Patch0134: 0134-format-table-make-sure-we-never-call-memcmp-with-NUL.patch
Patch0135: 0135-format-table-use-right-field-for-display.patch
Patch0136: 0136-format-table-add-option-to-uppercase-cells-on-displa.patch
Patch0137: 0137-format-table-never-try-to-reuse-cells-that-have-colo.patch
Patch0138: 0138-locale-util-add-logic-to-output-smiley-emojis-at-var.patch
Patch0139: 0139-analyze-add-new-security-verb.patch
Patch0140: 0140-tests-add-a-rudimentary-fuzzer-for-server_process_sy.patch
Patch0141: 0141-journald-make-it-clear-that-dev_kmsg_record-modifies.patch
Patch0142: 0142-journald-free-the-allocated-memory-before-returning-.patch
Patch0143: 0143-tests-rework-the-code-fuzzing-journald.patch
Patch0144: 0144-journald-make-server_process_native_message-compatib.patch
Patch0145: 0145-tests-add-a-fuzzer-for-server_process_native_message.patch
Patch0146: 0146-tests-add-a-fuzzer-for-sd-ndisc.patch
Patch0147: 0147-ndisc-fix-two-infinite-loops.patch
Patch0148: 0148-tests-add-reproducers-for-several-issues-uncovered-w.patch
Patch0149: 0149-tests-add-a-reproducer-for-an-infinite-loop-in-ndisc.patch
Patch0150: 0150-tests-add-a-reproducer-for-another-infinite-loop-in-.patch
Patch0151: 0151-fuzz-rename-fuzz-corpus-directory-to-just-fuzz.patch
Patch0152: 0152-test-add-testcase-for-issue-10007-by-oss-fuzz.patch
Patch0153: 0153-fuzz-unify-the-fuzz-regressions-directory-with-the-m.patch
Patch0154: 0154-test-bus-marshal-use-cescaping-instead-of-hexmem.patch
Patch0155: 0155-meson-add-Dlog-trace-to-set-LOG_TRACE.patch
Patch0156: 0156-meson-allow-building-resolved-and-machined-without-n.patch
Patch0157: 0157-meson-drop-duplicated-condition.patch
Patch0158: 0158-meson-use-.source_root-in-more-places.patch
Patch0159: 0159-meson-treat-all-fuzz-cases-as-unit-tests.patch
Patch0160: 0160-fuzz-bus-message-add-fuzzer-for-message-parsing.patch
Patch0161: 0161-bus-message-use-structured-initialization-to-avoid-u.patch
Patch0162: 0162-bus-message-avoid-an-infinite-loop-on-empty-structur.patch
Patch0163: 0163-bus-message-let-s-always-use-EBADMSG-when-the-messag.patch
Patch0164: 0164-bus-message-rename-function-for-clarity.patch
Patch0165: 0165-bus-message-use-define.patch
Patch0166: 0166-bus-do-not-print-null-if-the-message-has-unknown-typ.patch
Patch0167: 0167-bus-message-fix-calculation-of-offsets-table.patch
Patch0168: 0168-bus-message-remove-duplicate-assignment.patch
Patch0169: 0169-bus-message-fix-calculation-of-offsets-table-for-arr.patch
Patch0170: 0170-bus-message-drop-asserts-in-functions-which-are-wrap.patch
Patch0171: 0171-bus-message-output-debug-information-about-offset-tr.patch
Patch0172: 0172-bus-message-fix-skipping-of-array-fields-in-gvariant.patch
Patch0173: 0173-bus-message-also-properly-copy-struct-signature-when.patch
Patch0174: 0174-fuzz-bus-message-add-two-test-cases-that-pass-now.patch
Patch0175: 0175-bus-message-return-EBADMSG-not-EINVAL-on-invalid-gva.patch
Patch0176: 0176-bus-message-avoid-wrap-around-when-using-length-read.patch
Patch0177: 0177-util-do-not-use-stack-frame-for-parsing-arbitrary-in.patch
Patch0178: 0178-travis-enable-ASan-and-UBSan-on-RHEL8.patch
Patch0179: 0179-tests-keep-SYS_PTRACE-when-running-under-ASan.patch
Patch0180: 0180-tree-wide-various-ubsan-zero-size-memory-fixes.patch
Patch0181: 0181-util-introduce-memcmp_safe.patch
Patch0182: 0182-test-socket-util-avoid-memleak-reported-by-valgrind.patch
Patch0183: 0183-sd-journal-escape-binary-data-in-match_make_string.patch
Patch0184: 0184-capability-introduce-CAP_TO_MASK_CORRECTED-macro-rep.patch
Patch0185: 0185-sd-bus-use-size_t-when-dealing-with-memory-offsets.patch
Patch0186: 0186-sd-bus-call-cap_last_cap-only-once-in-has_cap.patch
Patch0187: 0187-mount-point-honour-AT_SYMLINK_FOLLOW-correctly.patch
Patch0188: 0188-travis-switch-from-trusty-to-xenial.patch
Patch0189: 0189-test-socket-util-Add-tests-for-receive_fd_iov-and-fr.patch
Patch0190: 0190-socket-util-Introduce-send_one_fd_iov-and-receive_on.patch
Patch0191: 0191-core-swap-order-of-n_storage_fds-and-n_socket_fds-pa.patch
Patch0192: 0192-execute-use-our-usual-syntax-for-defining-bit-masks.patch
Patch0193: 0193-core-introduce-new-Type-exec-service-type.patch
Patch0194: 0194-man-document-the-new-Type-exec-type.patch
Patch0195: 0195-sd-bus-allow-connecting-to-the-pseudo-container-.hos.patch
Patch0196: 0196-sd-login-let-s-also-make-sd-login-understand-.host.patch
Patch0197: 0197-test-add-test-for-Type-exec.patch
Patch0198: 0198-journal-gateway-explicitly-declare-local-variables.patch
Patch0199: 0199-tools-drop-unused-variable.patch
Patch0200: 0200-journal-gateway-use-localStorage-cursor-only-when-it.patch
Patch0201: 0201-sd-bus-deal-with-cookie-overruns.patch
Patch0202: 0202-journal-remote-do-not-request-Content-Length-if-Tran.patch
Patch0203: 0203-journal-do-not-remove-multiple-spaces-after-identifi.patch
Patch0204: 0204-cryptsetup-Do-not-fallback-to-PLAIN-mapping-if-LUKS-.patch
Patch0205: 0205-cryptsetup-call-crypt_load-for-LUKS-only-once.patch
Patch0206: 0206-cryptsetup-Add-LUKS2-token-support.patch
Patch0207: 0207-udev-scsi_id-fix-incorrect-page-length-when-get-devi.patch
Patch0208: 0208-Change-job-mode-of-manager-triggered-restarts-to-JOB.patch
Patch0209: 0209-bash-completion-analyze-support-security.patch
Patch0210: 0210-man-note-that-journal-does-not-validate-syslog-field.patch
Patch0211: 0211-rules-skip-memory-hotplug-on-ppc64.patch
Patch0212: 0212-mount-simplify-proc-self-mountinfo-handler.patch
Patch0213: 0213-mount-rescan-proc-self-mountinfo-before-processing-w.patch
Patch0214: 0214-swap-scan-proc-swaps-before-processing-waitid-result.patch
Patch0215: 0215-analyze-security-fix-potential-division-by-zero.patch
Patch0216: 0216-journal-rely-on-_cleanup_free_-to-free-a-temporary-s.patch
Patch0217: 0217-shared-but-util-drop-trusted-annotation-from-bus_ope.patch
Patch0218: 0218-sd-bus-adjust-indentation-of-comments.patch
Patch0219: 0219-resolved-do-not-run-loop-twice.patch
Patch0220: 0220-resolved-allow-access-to-Set-Link-and-Revert-methods.patch
Patch0221: 0221-resolved-query-polkit-only-after-parsing-the-data.patch

# disable test to enable building with "systemd-nspawn" (+ COPR)
Patch9990: 9990-disable-test-mount-util.patch


%ifarch %{ix86} x86_64 aarch64
%global have_gnu_efi 1
%endif

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  libcap-devel
BuildRequires:  libmount-devel
BuildRequires:  pam-devel
BuildRequires:  libselinux-devel
BuildRequires:  audit-libs-devel
BuildRequires:  cryptsetup-devel
BuildRequires:  dbus-devel
BuildRequires:  libacl-devel
BuildRequires:  gobject-introspection-devel
BuildRequires:  libblkid-devel
BuildRequires:  xz-devel
BuildRequires:  xz
BuildRequires:  lz4-devel
BuildRequires:  lz4
BuildRequires:  bzip2-devel
BuildRequires:  libidn2-devel
BuildRequires:  libcurl-devel
BuildRequires:  kmod-devel
BuildRequires:  elfutils-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  libgpg-error-devel
BuildRequires:  gnutls-devel
BuildRequires:  libmicrohttpd-devel
BuildRequires:  libxkbcommon-devel
BuildRequires:  iptables-devel
BuildRequires:  libxslt
BuildRequires:  docbook-style-xsl
BuildRequires:  pkgconfig
BuildRequires:  gperf
BuildRequires:  gawk
BuildRequires:  tree
BuildRequires:  python3-devel
BuildRequires:  python3-lxml
BuildRequires:  firewalld-filesystem
%if 0%{?have_gnu_efi}
BuildRequires:  gnu-efi gnu-efi-devel
%endif
BuildRequires:  libseccomp-devel
BuildRequires:  git
BuildRequires:  meson >= 0.43
BuildRequires:  gettext

Requires(post): coreutils
Requires(post): sed
Requires(post): acl
Requires(post): grep
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd
Requires:       dbus >= 1.9.18
Requires:       util-linux

%description
This package contains systemd-networkd a daemon to manage simple network
configurations.


%prep
%autosetup -n systemd-%{?gitcommit:%{gitcommit}}%{!?gitcommit:%{version}} -S git_am

%build
%define ntpvendor %(source /etc/os-release; echo ${ID})
%{!?ntpvendor: echo 'NTP vendor zone is not set!'; exit 1}

CONFIGURE_OPTS=(
        -Dsysvinit-path=/etc/rc.d/init.d
        -Drc-local=/etc/rc.d/rc.local
        -Dntp-servers='0.%{ntpvendor}.pool.ntp.org 1.%{ntpvendor}.pool.ntp.org 2.%{ntpvendor}.pool.ntp.org 3.%{ntpvendor}.pool.ntp.org'
        -Ddns-servers=''
        -Ddev-kvm-mode=0666
        -Dkmod=true
        -Dxkbcommon=true
        -Dblkid=true
        -Dseccomp=true
        -Dima=true
        -Dselinux=true
        -Dapparmor=false
        -Dpolkit=true
        -Dxz=true
        -Dzlib=true
        -Dbzip2=true
        -Dlz4=true
        -Dpam=true
        -Dacl=true
        -Dsmack=true
        -Dgcrypt=true
        -Daudit=true
        -Delfutils=true
        -Dlibcryptsetup=true
        -Delfutils=true
        -Dqrencode=false
        -Dgnutls=true
        -Dmicrohttpd=true
        -Dlibidn2=true
        -Dlibiptc=true
        -Dlibcurl=true
        -Defi=true
        -Dgnu-efi=%{?have_gnu_efi:true}%{?!have_gnu_efi:false}
        -Dtpm=true
        -Dhwdb=true
        -Dsysusers=true
        -Ddefault-kill-user-processes=false
        -Dtests=unsafe
        -Dinstall-tests=false
        -Dtty-gid=5
        -Dusers-gid=100
        -Dnobody-user=nobody
        -Dnobody-group=nobody
        -Dsplit-usr=false
        -Dsplit-bin=true
        -Db_lto=false
        -Dnetworkd=true
        -Dtimesyncd=false
        -Ddefault-hierarchy=legacy
)

%meson "${CONFIGURE_OPTS[@]}"
%meson_build


%install
%meson_install

cd %{buildroot}

find . -type f | grep -v network > .systemd-files.txt
# symbolic links
find . -type l | grep -v network >> .systemd-files.txt
cat .systemd-files.txt | xargs --no-run-if-empty -n1 -IFILE rm %{buildroot}/FILE

# "systemd" package already provides "nonetwork/service.conf"
rm %{buildroot}%{_prefix}/lib/systemd/portable/profile/nonetwork/service.conf

# remove all empty directories
find . -type d -empty -delete

find %{buildroot}

%check
%meson_test

#############################################################################################

%pre
getent group systemd-network &>/dev/null || groupadd -r -g 192 systemd-network 2>&1 || :
getent passwd systemd-network &>/dev/null || useradd -r -u 192 -l -g systemd-network -d / -s /sbin/nologin -c "systemd Network Management" systemd-network &>/dev/null || :

%post
# Services we install by default, and which are controlled by presets.
if [ $1 -eq 1 ] ; then
        systemctl preset --quiet \
                systemd-networkd.service \
                systemd-networkd-wait-online.service \
                >/dev/null || :
fi


%preun
if [ $1 -eq 0 ] ; then
        systemctl disable --quiet \
                systemd-networkd.service \
                systemd-networkd-wait-online.service \
                >/dev/null || :
fi

%global _docdir_fmt systemd

%files
%license LICENSE.GPL2 LICENSE.LGPL2.1
%{_bindir}/networkctl

%{_sysconfdir}/systemd/system/dbus-org.freedesktop.network1.service
%{_sysconfdir}/systemd/system/multi-user.target.wants/systemd-networkd.service
%{_sysconfdir}/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service
%{_sysconfdir}/systemd/system/sockets.target.wants/systemd-networkd.socket

%{_prefix}/lib/systemd/systemd-networkd
%{_prefix}/lib/systemd/systemd-networkd-wait-online
%{_unitdir}/network-online.target
%{_unitdir}/systemd-networkd.service
%{_unitdir}/systemd-networkd-wait-online.service
%{_unitdir}/systemd-networkd.socket
%{_unitdir}/network.target
%{_unitdir}/network-pre.target

%{_datadir}/polkit-1/rules.d/systemd-networkd.rules
%{_datadir}/dbus-1/system-services/org.freedesktop.network1.service
%{_datadir}/dbus-1/system.d/org.freedesktop.network1.conf

# "systemd" package already provides "/usr/lib/systemd/network" directory
%{_prefix}/lib/systemd/network/80-container-host0.network
%{_prefix}/lib/systemd/network/99-default.link
%{_prefix}/lib/systemd/network/80-container-vz.network
%{_prefix}/lib/systemd/network/80-container-ve.network

%{_mandir}/man1/networkctl.*
%{_mandir}/man5/systemd.network.*
%{_mandir}/man5/networkd*
%{_mandir}/man8/systemd-networkd*

# "…/bash-completion/completions" is owned by "filesystem", no need to specify
# this explicitely in "Requires:"
%{_datadir}/bash-completion/completions/networkctl

# "/usr/share/zsh" is not owned by any package
# "…/zsh/site-functions" is owned by curl
# likely a packaging error in RHEL 8 / Fedora 30
%{_datadir}/zsh/site-functions/_networkctl


%changelog
* Wed Jan 15 2020 Felix Schwarz <fschwarz@fedoraproject.org> - 239-18.el8_1.1
- update package to 239-18.el8_1.1

* Wed Oct 16 2019 Felix Schwarz <fschwarz@fedoraproject.org> - 239-13_0.5.1
- initial packaging of systemd-networkd based on systemd RPM from CentOS 8

