# Контроли host_audit

Роль читает систему и складывает результат на управляющую машину: `/tmp/ansible/host-audit/<host>-host-audit.txt` и рядом JSON с тем же именем. `<host>` — каталог хоста в `host_vars`. Ниже — что именно считается успехом и что обычно нужно поменять. Команды ниже — ориентир для администратора, роль их сама не выполняет.

Серьёзность в отчёте относится к нарушению. При `host_audit_fail_on: high` плейбук падает на `high` и `critical`. `warn` и `skip` прогон не останавливают.

## SSH-01. Только ключи

Успех: и `sshd -T`, и разбор файлов дают `PasswordAuthentication no`, ни один `Match` не ставит `yes`, процесс `sshd` не старше файлов.

Порядок такой, как у OpenSSH: первое значение побеждает, `Include` раскрывается в месте, где он написан, маска `sshd_config.d/*.conf` сортируется по имени. Проверять только `/etc/ssh/sshd_config` недостаточно.

Исправление: в самом раннем файле, обычно `sshd_config.d/00-….conf`, записать `PasswordAuthentication no` и выполнить `systemctl reload ssh` (на RHEL сервис называется `sshd`). Убедиться, что `sshd -T | grep passwordauthentication` печатает `no`.

## SSH-02. Root по SSH закрыт

Успех: `PermitRootLogin no`.

`yes`, пустое значение, `prohibit-password`, `without-password` и `forced-commands-only` — нарушение. Первые два пускают root по паролю или по умолчанию, остальные оставляют вход root по ключу.

Исправление то же, что у SSH-01: первое полученное значение должно быть `PermitRootLogin no`, затем reload.

## SSH-03. Ключи управляющей машины

Каталоги из `host_audit_controller_key_dirs` (по умолчанию `~/.ssh` на машине, где запущен Ansible). Успех: каждый найденный приватный ключ зашифрован, режим не шире `0600`. Отсутствие ключей — тоже успех: фразы не у чего требовать. Неизвестный формат даёт `warn`.

Проверка смотрит заголовок OpenSSH (`cipher none` / `kdf none`), PEM `Proc-Type: 4,ENCRYPTED`, PKCS#8 и PuTTY `Encryption:`. Содержимое ключа в отчёт не попадает, парольная фраза не перебирается.

Исправление: `ssh-keygen -p -f ~/.ssh/id_ed25519` и `chmod 600` на файл ключа.

Отключение: `host_audit_check_controller_keys: false` (контроль станет `skip`).

## SSH-04. Ключи на целевом хосте

Сканируются `/home` и `/root` на глубину `host_audit_max_key_depth`. Ключи хоста в `/etc/ssh` сюда не входят: они нужны демону и почти всегда без фразы.

Нарушение: приватный ключ без фразы или с доступом группы/остальных. Зашифрованный ключ с режимом `0600` — `warn`: на сервере ему всё равно не место, вход должен идти через агент на управляющей машине. Нет ключей — `pass`.

## SSH-05. Кто может подключаться

Успех: в эффективной конфигурации есть `AllowUsers` или `AllowGroups`, и это не `*`, `*@*` или пустой список. Запись `auditor` или `auditor@10.0.0.0/24` подходит: второе одновременно ограничивает и пользователя, и адрес.

`Match Address` без списка пользователей не считается ограничением. Несовпавший клиент продолжает пользоваться глобальными правилами, где по умолчанию разрешены все.

Исправление: `AllowUsers auditor` или `AllowUsers auditor@10.1.0.0/24` в том файле, который задаёт первое значение, затем reload.

## SSH-06. Блокировка перебора

Успех, если выполняется любое из условий:

- `fail2ban` запущен и `fail2ban-client status sshd` возвращает 0;
- запущен `sshguard`;
- запущены `crowdsec` и firewall bouncer (`crowdsec-firewall-bouncer`, `crowdsec-nftables-bouncer` или `crowdsec-custom-bouncer`).

Запущенный fail2ban без jail `sshd` — нарушение. Исправление: пакет `fail2ban`, файл `/etc/fail2ban/jail.d/sshd.local` с `enabled = true`, `systemctl enable --now fail2ban`.

## SSH-07. MFA на управляющем контуре

На обычных хостах контроль пропускается. Для бастиона и админских ВМ задайте `host_audit_management_host: true`.

Успех одновременно:

- каждый вариант `AuthenticationMethods` содержит `publickey` и ещё хотя бы один фактор (`publickey,keyboard-interactive`); отдельный вариант из одного `publickey` позволяет обойти второй фактор, потому что списки объединяются через ИЛИ;
- `UsePAM yes`;
- если используется `keyboard-interactive`, то `KbdInteractiveAuthentication yes`;
- в `/etc/pam.d/sshd` или в файле, который он включает, есть `required` или `requisite` на один из модулей: `pam_google_authenticator.so`, `pam_oath.so`, `pam_duo.so`, `pam_u2f.so`, `pam_yubico.so`, `pam_securid.so`;
- соответствующий `.so` лежит в `/lib`, `/usr/lib`, `/lib64` или `/usr/lib64`.

`optional` и `sufficient` не считаются вторым фактором. Роль не моделирует весь стек PAM, поэтому модуль должен быть явно обязательным.

## SUD-01. sudo

Читаются `/etc/sudoers`, `/etc/sudoers.d` и пути из `#include` / `#includedir`.

- `NOPASSWD: ALL` у кого угодно, кроме правила только для `root`, — `critical`.
- Выдача всех команд с запросом пароля (`%sudo ALL=(ALL) ALL` и похожие) — `medium`, статус контроля при этом всё равно `fail`.
- Конкретная команда, в том числе с `NOPASSWD`, не нарушает этот контроль.
- Режим файла шире `0440` — нарушение.

Правило `root ALL=(ALL) ALL` допустимо. Алиас команд раскрывается на один уровень: `Cmnd_Alias EVERYTHING = ALL` и затем `NOPASSWD: EVERYTHING` будет найдено.

Исправление: удалить широкие правила и оставить перечень команд. Пример: `auditor ALL=(root) /usr/bin/systemctl status ssh`.

## HRN-01. Параметры ядра

Список и операция сравнения лежат в `host_audit_sysctl`. По умолчанию это пересылки, source route, redirects, martians, syncookies, reverse path, ASLR, дампы suid, `dmesg_restrict`, `kptr_restrict` и `ptrace_scope`. Ключи IPv6 необязательны: если стек выключен, проверка этого ключа пропускается.

`host_audit_sysctl_skip` убирает ключ из решения (статус `skip`). Так можно отметить параметр, который в конкретной среде нельзя изменить, не ослабляя остальные.

Исправление: `/etc/sysctl.d/99-hardening.conf` и `sysctl --system`. Значение читается из живого ядра, а не из файла.

## HRN-02. Права на файлы

Потолок задан в `host_audit_file_modes`: фактический режим не должен быть шире указанного, владелец `root`. Более строгий режим проходит. Отсутствующий необязательный путь (cron на системе без cron) даёт `skip`.

Дополнительно каждый файл в `/etc/ssh/sshd_config.d` должен быть не шире `0600` и принадлежать `root:root`.

Ориентир: `sshd_config` и drop-in — `0600`, `shadow`/`gshadow` — не шире `0640`, каталоги cron — `0700`, `/etc/crontab` — `0600`.

## HRN-03. Парольная политика

Проверяется, даже когда SSH-пароль выключен: локальный `su`, консоль и sudo остаются.

| Проверка | Порог по умолчанию |
| --- | --- |
| `PASS_MAX_DAYS` | от 1 до 365 |
| `PASS_MIN_DAYS` | не меньше 1 |
| `PASS_WARN_AGE` | не меньше 7 |
| `ENCRYPT_METHOD` | `SHA512` или `yescrypt` |
| `pwquality` `minlen` | не меньше 14 |
| сложность | `minclass` не меньше 4 или все `*credit` не больше `-1` |
| PAM | есть `pam_pwquality.so` |
| история | `remember` не меньше 5 |
| блокировка | `pam_faillock.so` или `pam_tally2.so`, `deny` от 1 до 5, `unlock_time` 0 или не меньше 900 |
| `INACTIVE` в `/etc/default/useradd` | от 0 до 30 |
| `/etc/shadow` | нет пустого поля пароля |

Пороги меняются в `host_audit_password_policy`.

## UPD-01. Обновления безопасности

Debian и Ubuntu: установлен `unattended-upgrades`, в `apt.conf.d` есть незакомментированные `APT::Periodic::Unattended-Upgrade "1"` и origin с `-security` или `esm`, таймер `apt-daily-upgrade` включён.

RHEL и совместимые: установлен `dnf-automatic`, таймер `dnf-automatic` или `dnf-automatic-install` включён, в `/etc/dnf/automatic.conf` стоят `apply_updates = yes` и `upgrade_type = security`.

Другие семейства получают `warn`: роль не угадывает их механизм обновлений.

## FW-01. Firewall

Берётся первый подходящий слой: активный ufw, затем запущенный firewalld, затем nftables с цепочкой `hook input`, затем `iptables -S`, если есть политика `INPUT`.

Успех:

- политика входа — deny/reject/drop, а не accept; у firewalld цель `default` тоже считается default-deny;
- принятые TCP/UDP-порты являются подмножеством `host_audit_allowed_tcp_ports` и `host_audit_allowed_udp_ports` (по умолчанию только TCP 22);
- нет правила ACCEPT без порта, кроме loopback, established/related и ICMP;
- сервис ufw, firewalld или nftables включён и переживёт перезагрузку. Для голого iptables отсутствие persistence — `warn`.

Незнакомый сервис firewalld не сопоставляется с портом молча и считается лишним открытием. `dhcpv6-client` портом не считается.

## SVC-01. Поверхность

Три независимые проверки плюс UID 0:

- пакеты из `host_audit_forbidden_packages` не установлены (telnet, rsh, tftp, nis, xinetd и соседние);
- сервисы из `host_audit_forbidden_services` не running и не enabled; отсутствующий unit — не нарушение;
- учётка из `host_audit_demo_accounts` либо отсутствует, либо не может открыть сессию: shell `nologin` или `false`;
- единственный UID 0 — `root` (`critical`, если это не так).

Имена в списках — политика репозитория. Боевой набор, который вам нужен, уберите из списка переменной, а не из задачи.

## AUD-01. auditd

В `/etc/audit/rules.d/*.rules` или `/etc/audit/audit.rules` должны быть:

- наблюдение за `/etc/passwd` и `/etc/shadow`;
- наблюдение за `/etc/sudoers`;
- правило смены времени (`adjtimex`, `settimeofday`, `clock_settime` или ключ `time-change`).

Сервис `auditd` должен быть enabled и запущен. Если `auditctl` сообщает, что ядро не поддерживает audit или запрещает вызов, правила на месте и unit включён, статус `service_active` становится `warn`. Так бывает в контейнере. На обычном сервере это не смягчается: демон обязан работать.

## LOG-01. Центральные логи

Ищется незакомментированная настройка и запущенный сервис:

- rsyslog: `@@host`, `@host`, `omfwd` или `target=`;
- `systemd-journal-upload`: `URL=`;
- filebeat: `output.logstash`, `output.elasticsearch` или `output.kafka`;
- vector: выход `elasticsearch`, `kafka`, `socket` или `http`.

Доступность приёмника не проверяется. Конфигурация без запущенного сервиса — нарушение.

## TIM-01. Время

Успех: запущен один из `chrony`, `chronyd`, `systemd-timesyncd`, `ntp`, `ntpd`, `ntpsec`, и задан источник — `server`/`pool` в chrony или ntp, либо `NTP`/`FallbackNTP` в timesyncd, либо непустой ответ `timedatectl show-timesync`.

При `host_audit_time_require_synchronized: true` (значение по умолчанию) `timedatectl` должен показать `NTPSynchronized=yes`. Для контейнера, где синхронизация заведомо невозможна, переменную ставят в `false`: проверка часов пропускается, а отсутствие службы по-прежнему ломает контроль.
