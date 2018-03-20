NtdsAudit is an application to assist in auditing Active Directory databases.

It provides some useful statistics relating to accounts and passwords, as shown in the following example. It can also be used to dump password hashes for later cracking. 

```
Account stats for: domain.local
  Disabled users _____________________________________________________   418 of  5164 (8%)
  Expired users ______________________________________________________    67 of  5164 (1%)
  Active users unused in 1 year ______________________________________   787 of  4679 (17%)
  Active users unused in 90 days _____________________________________  1240 of  4679 (27%)
  Active users which do not require a password _______________________   156 of  4679 (3%)
  Active users with non-expiring passwords ___________________________  3907 of  4679 (84%)
  Active users with password unchanged in 1 year _____________________  1006 of  4679 (22%)
  Active users with password unchanged in 90 days ____________________  1400 of  4679 (30%)
  Active users with Administrator rights _____________________________    63 of  4679 (1%)
  Active users with Domain Admin rights ______________________________    54 of  4679 (1%)
  Active users with Enterprise Admin rights __________________________     0 of  4679 (0%)

  Disabled computer accounts _________________________________________    86 of  1414 (6%)

Password stats for: domain.local
  Active users using LM hashing ______________________________________    40 of  4679 (1%)
  Active users with duplicate passwords ______________________________  2312 of  4679 (49%)
  Active users with password stored using reversible encryption ______  4666 of  4679 (100%)
```

### Usage
NtdsAudit requires version 4.6 or newer of the .NET framework.

```
Usage:  [arguments] [options]

Arguments:
  NTDS file  The path of the NTDS.dit database to be audited, required.

Options:
  -v | --version            Show version information
  -h | --help               Show help information
  -s | --system <file>      The path of the associated SYSTEM hive, required when using the pwdump option.
  -p | --pwdump <file>      The path to output hashes in pwdump format.
  -u | --users-csv <file>   The path to output user details in CSV format.
  --history-hashes          Include history hashes in the pdwump output.
  --dump-reversible <file>  The path to output clear text passwords, if reversible encryption is enabled.
  --wordlist                The path to a wordlist of weak passwords for basic hash cracking. Warning, using this option is slow, the use of a dedicated password cracker, such as 'john', is recommended instead.
  --base-date <yyyyMMdd>    Specifies a custom date to be used as the base date in statistics. The last modified date of the NTDS file is used by default.
  --debug                   Show debug output.

WARNING: Use of the --pwdump option will result in decryption of password hashes using the System Key.
Sensitive information will be stored in memory and on disk. Ensure the pwdump file is handled appropriately
```

For example, the following command will display statistics, output a file `pwdump.txt` containing password hashes, and output a file `users.csv` containing details for each user account.

```
ntdsaudit ntds.dit -s SYSTEM -p pwdump.txt -u users.csv
```

### Obtaining the required files
NtdsAudit requires the `ntds.dit` Active Directory database, and optionally the `SYSTEM` registry hive if dumping password hashes. These files are locked by a domain controller and as such cannot be simply copy and pasted. The recommended method of obtaining these files from a domain controller is using the builtin `ntdsutil` utility. 

* Open a command prompt (cmd.exe) as an administrator. To open a command prompt as an administrator, click Start. In Start Search, type Command Prompt. At the top of the Start menu, right-click Command Prompt, and then click Run as administrator. If the User Account Control dialog box appears, enter the appropriate credentials (if requested) and confirm that the action it displays is what you want, and then click Continue.

* At the command prompt, type the following command, and then press ENTER:

```
ntdsutil
```

* At the ntdsutil prompt, type the following command, and then press ENTER:

```
activate instance ntds
```

* At the ntdsutil prompt, type the following command, and then press ENTER:

```
ifm
```

* At the ifm prompt, type the following command, and then press ENTER:

```
create full <Drive>:\<Folder>
```

Where `<Drive>:\<Folder>` is the path to the folder where you want the files to be created. 
