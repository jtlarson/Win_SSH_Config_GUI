# Win_SSH_Config_GUI

An SSH config GUI for Windows. Supports easy editing and launching SSH / WinSCP sessions (including multi-tab Windows Terminal sessions).

* Edit general properties shared by all hosts
* Edit host properties individually or in groups
* Open one or more hosts in multi-pane Windows Terminal session
* Add SSH pane to current Windows terminal session
* Open WinSCP (SFTP/SCP client) connection to selected host(s)
* Assign searchable group names to hosts. 

## Requirements (for full functionality)
1. [Windows Terminal](https://learn.microsoft.com/windows/terminal/)  
2. [Windows OpenSSH (client/server)](https://learn.microsoft.com/windows-server/administration/openssh/openssh_overview)  
3. [WinSCP (SFTP/FTP GUI client)](https://winscp.net/eng/docs/start)  
4. [Pageant (PuTTY SSH key agent)](https://www.putty.org/) (or another ssh key agent)

## Setup guide
1. Create your OpenSSH config file at:
   - `%USERPROFILE%\.ssh\config`  
   - (Typically `C:\Users\<YourUserName>\.ssh\config`)  
   - See the OpenSSH config reference: https://learn.microsoft.com/windows-server/administration/openssh/openssh_config

2. Place this script in your user folder (for example `C:\Users\<YourUserName>\`).

3. Create a shortcut with the following properties.

   Target (recommended — PowerShell 7+):
       
       "C:\Program Files\PowerShell\7\pwsh.exe" -STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ".\Win_SSH_Config_GUI.ps1"

   Shortcut properties:
   - Start in: `%USERPROFILE%`  
   - Run: Minimized

## Notes
- `ExecutionPolicy Bypass` in the shortcut is a convenience for running unsigned local scripts. 
- The -STA option starts PowerShell in Single-Threaded Apartment (STA) mode. It’s required since this script uses WPF and features like the clipboard, drag‑and‑drop, or OLE dialogs.
