
# SecRev

SecRev is a Python application that retrieves and reports inactive Active Directory users, Active Directory groups and members, and the NTFS permissions of specified file shares. It generates an Excel report to display this information.

Supports Active Directory environments running Server 2012 R2 or newer. (PowerShell 3 is a requirement)



## Installation

Clone the repository:
```bash
git clone https://github.com/trenttownsend/SecRev.git
```

Navigate to the project directory:
```bash
cd SecRev
```

Install the required dependencies:
```bash
pip install -r requirements.txt
```

Build the executable:
```py
pyinstaller --onefile --name SecRev --console --add-data "users-groups.ps1;." --add-data "share-permissions.ps1;." --add-binary "%LOCALAPPDATA%\\Programs\\Python\\Python310\\python.exe;." --add-binary "%LOCALAPPDATA%\\Programs\\Python\\Python310\\python310.dll;." SecRev.py
```
Please note, you may have to update these binaries. Python 3.10 and 3.11 are working.
## Usage/Examples

To run SecRev, use the following syntax:
```bash
usage: SecRev.exe [-h] [-SAVETO path] [-s FILESERVER share1 "share 2" ... shareN] [-s ...]
example: SecRev.exe -s VM-FS "Finance Reports" Logging Users -s VM-SQL Data "User Files"

-h
    Shows help

-SAVETO path
    The path where you want to save the report (e.g., C:\temp). If no path is specified, the default path will be C:\temp.

-s FILESERVER [SHARE ...]
    Specify the file server and an arbitrary number of shares (e.g., -s FILESERVER share1 share2).
```

The files 'ignore-users.txt', 'ignore-groups.txt', and 'convert-users.txt' are used to modify the output of the program.
