# password-in-command

This rule checks task definitions for calls to command or shell tasks
that might include credentials in the command line. This has the
potential to leak those credentials into Ansible logs that might be
automatically exported to other logging systems. If passwords need
to be provided on the command line, the task should use no_log = true
to prevent the task details from being logged.

## Problematic Code

```yaml
---
# Command tasks include passwords but no_log is false
- name: Example playbook
  hosts: localhost
  tasks:
    - name: Run arbitrary command with passwords
      ansible.builtin.command:
        cmd: /usr/bin/runprocess.sh -user db_user -pass {{ my_secret }}
        creates: /path/to/output
        no_log: false
    - name: Run arbitrary command with passwords
      ansible.builtin.command: /usr/bin/runprocess.sh db_user {{ password }}
      args:
        creates: /path/to/output
```

## Correct Code

```yaml
---
# Command tasks include passwords but no_log is true
- name: Example playbook
  hosts: localhost
  tasks:
    - name: Run arbitrary command with passwords
      ansible.builtin.command:
        cmd: /usr/bin/runprocess.sh -user db_user -pass {{ my_secret }}
        creates: /path/to/output
        no_log: true
    - name: Run arbitrary command with passwords
      ansible.builtin.command: /usr/bin/runprocess.sh db_user {{ password }}
      args:
        creates: /path/to/output
        no_log: true
```
