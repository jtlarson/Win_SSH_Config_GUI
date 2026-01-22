# Win_SSH_Config_GUI
# Shortcut: "C:\Program Files\PowerShell\7\pwsh.exe" -STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File.\Win_SSH_Config_GUI.ps1
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,Microsoft.VisualBasic

# ----------------------------
# === Settings (user-editable)
# ----------------------------
# Core config variables (user requested explicit variables)
$SshConfigPath = Join-Path $env:USERPROFILE ".ssh\config"
$BackupFolder = Join-Path $env:USERPROFILE ".ssh\config_backups"
$GroupPrefix = '# GROUP:'
$EscapedGroupPrefix = [regex]::Escape($GroupPrefix)

# Executable and detection settings (edit here if desired)
$Settings = @{
    WTPath = "wt.exe"                # Windows Terminal executable (keep "wt.exe" if in PATH)
    WinSCPPath = ""                  # Explicit WinSCP path (leave empty to auto-detect)
    WinSCPCandidates = @(
        "$env:ProgramFiles\WinSCP\WinSCP.exe",
        "$env:ProgramFiles(x86)\WinSCP\WinSCP.exe",
        "$env:USERPROFILE\AppData\Local\Programs\WinSCP\WinSCP.exe",
        "$PSScriptRoot\WinSCP\WinSCP.exe"
    )
    Editor = ""                      # Editor command (e.g. 'code --wait' or full path), blank = auto-detect
    UndoStackLimit = 50              # Maximum undo/redo history
    RecentGroupsLimit = 10           # Number of recent groups to remember
}

# New WT settings with sensible defaults (persisted)
$Settings.WTAttachToExistingWindow = $true
$Settings.WTProfile = ""

# Settings persistence locations
$SettingsDir = Join-Path $env:APPDATA 'Win_SSH_Config_GUI'
$SettingsFilePath = Join-Path $SettingsDir 'settings.json'

function Load-Settings {
    if (-not (Test-Path $SettingsFilePath)) { return }
    try {
        $json = Get-Content -Path $SettingsFilePath -Raw -ErrorAction Stop
        if (-not $json) { return }
        $obj = $json | ConvertFrom-Json -ErrorAction Stop
        foreach ($prop in $obj.PSObject.Properties.Name) {
            $Settings[$prop] = $obj.$prop
        }
    } catch {
        Write-Host "Warning: failed to load settings: $($_.Exception.Message)"
    }
}

function Save-Settings {
    try {
        if (-not (Test-Path $SettingsDir)) { New-Item -ItemType Directory -Path $SettingsDir -Force | Out-Null }
        $ordered = [ordered]@{}
        foreach ($k in $Settings.Keys) { $ordered[$k] = $Settings[$k] }
        $ordered | ConvertTo-Json -Depth 6 | Set-Content -Path $SettingsFilePath -Encoding utf8
    } catch {
        [System.Windows.MessageBox]::Show("Failed to save settings: $($_.Exception.Message)","Settings Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
    }
}

# Load persisted settings (if present)
Load-Settings

# Auto-detect Editor if not set
if (-not $Settings.Editor -or $Settings.Editor.Trim() -eq "") {
    if ($env:EDITOR) { $Settings.Editor = $env:EDITOR }
    elseif (Get-Command code -ErrorAction SilentlyContinue) { $Settings.Editor = 'code --wait' }
    else { $Settings.Editor = 'notepad' }
}

# Recent groups tracking
$Global:RecentGroups = @()
$Global:HasUnsavedChanges = $false

# ----------------------------
# === Helpers
# ----------------------------
function Ensure-Paths {
    if (-not (Test-Path $SshConfigPath)) { New-Item -ItemType File -Path $SshConfigPath -Force | Out-Null }
    if (-not (Test-Path $BackupFolder)) { New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null }
}

function Backup-Config {
    Ensure-Paths
    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $dest = Join-Path $BackupFolder ("config.bak.$timestamp")
    try {
        Copy-Item -Path $SshConfigPath -Destination $dest -Force -ErrorAction Stop
    } catch {
        [System.Windows.MessageBox]::Show("Failed to create backup: $($_.Exception.Message)","Backup Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
    }
}

function Validate-Port {
    param([string]$port)
    if ([string]::IsNullOrWhiteSpace($port)) { return $true }
    $num = 0
    if ([int]::TryParse($port, [ref]$num)) {
        return ($num -ge 1 -and $num -le 65535)
    }
    return $false
}

function Add-RecentGroup {
    param([string]$groupName)
    if ([string]::IsNullOrWhiteSpace($groupName)) { return }
    $Global:RecentGroups = @($groupName) + ($Global:RecentGroups | Where-Object { $_ -ne $groupName })
    if ($Global:RecentGroups.Count -gt $Settings.RecentGroupsLimit) {
        $Global:RecentGroups = $Global:RecentGroups[0..($Settings.RecentGroupsLimit - 1)]
    }
}

# ----------------------------
# === Undo / Redo (session-only)
# ----------------------------
$Global:UndoStack = @()
$Global:RedoStack = @()

function Clone-Blocks($blocks) {
    $json = $blocks | ConvertTo-Json -Depth 50
    return $json | ConvertFrom-Json
}

function CanUndo { return ($Global:UndoStack.Count -gt 0) }
function CanRedo { return ($Global:RedoStack.Count -gt 0) }

function UpdateUndoStatus {
    if ($null -eq $StatusText) { return }
    $u = if (CanUndo) { "Undo available (Ctrl+Z)" } else { "No undo" }
    $r = if (CanRedo) { "Redo available (Ctrl+Y)" } else { "No redo" }
    $unsaved = if ($Global:HasUnsavedChanges) { " | UNSAVED CHANGES" } else { "" }
    $StatusText.Text = "$u | $r$unsaved"
}

function PushUndo([string]$label) {
    $snapshot = Clone-Blocks($Global:Blocks)
    $Global:UndoStack += ,@{ Snap = $snapshot; Label = $label }
    
    # Limit stack size
    if ($Global:UndoStack.Count -gt $Settings.UndoStackLimit) {
        $Global:UndoStack = $Global:UndoStack[($Global:UndoStack.Count - $Settings.UndoStackLimit)..($Global:UndoStack.Count - 1)]
    }
    
    $Global:RedoStack = @()
    $Global:HasUnsavedChanges = $true
    UpdateUndoStatus
}

function Undo {
    if (-not (CanUndo)) { 
        if ($null -ne $StatusText) { $StatusText.Text = "Nothing to undo" }
        return 
    }
    $current = Clone-Blocks($Global:Blocks)
    $Global:RedoStack += ,@{ Snap = $current; Label = "redo" }
    $last = $Global:UndoStack[-1]
    if ($Global:UndoStack.Count -eq 1) { 
        $Global:UndoStack = @() 
    } else { 
        $Global:UndoStack = $Global:UndoStack[0..($Global:UndoStack.Count-2)] 
    }
    $Global:Blocks = $last.Snap
    Refresh-List -filter $SearchBox.Text
    if ($null -ne $StatusText) { $StatusText.Text = "Undid: $($last.Label)" }
    UpdateUndoStatus
}

function Redo {
    if (-not (CanRedo)) { 
        if ($null -ne $StatusText) { $StatusText.Text = "Nothing to redo" }
        return 
    }
    $current = Clone-Blocks($Global:Blocks)
    $Global:UndoStack += ,@{ Snap = $current; Label = "undo" }
    $next = $Global:RedoStack[-1]
    if ($Global:RedoStack.Count -eq 1) { 
        $Global:RedoStack = @() 
    } else { 
        $Global:RedoStack = $Global:RedoStack[0..($Global:RedoStack.Count-2)] 
    }
    $Global:Blocks = $next.Snap
    Refresh-List -filter $SearchBox.Text
    if ($null -ne $StatusText) { $StatusText.Text = "Redid change" }
    UpdateUndoStatus
}

# ----------------------------
# === Parse / Write ssh_config
# ----------------------------
function Parse-SSHConfig {
    Ensure-Paths
    try {
        $text = Get-Content -Path $SshConfigPath -Encoding utf8 -Raw -ErrorAction Stop
    } catch {
        [System.Windows.MessageBox]::Show("Failed to read SSH config: $($_.Exception.Message)","Read Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
        return @()
    }
    
    if ($null -eq $text) { $text = "" }
    $lines = [System.Text.RegularExpressions.Regex]::Split($text, "`r?`n")
    $blocks = @()
    $current = @{ Type='global'; HeaderLines=@(); Lines=@(); HostPatterns=@(); Group=$null }
    $groupPattern = '^' + $EscapedGroupPrefix + '\s*(.+)$'

    for ($i=0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        $trim = $line.Trim()

        if ($trim -match $groupPattern -and $current.Type -ne 'host') {
            # Keep comment lines in header for now (we will normalize later)
            $current.HeaderLines += $line
            continue
        }

        if ($trim -match '^(?i)Host\s+(.+)$') {
            $blocks += $current
            $patterns = $Matches[1].Trim().Split() | Where-Object { $_ -ne '' }
            $group = $null
            foreach ($header in $current.HeaderLines) {
                if ($header.Trim() -match $groupPattern) {
                    $group = $Matches[1].Trim()
                    Add-RecentGroup -groupName $group
                }
            }
            $current = @{ Type='host'; HeaderLines = @($line); Lines = @(); HostPatterns = $patterns; Group = $group }
            continue
        } else {
            $current.Lines += $line
        }
    }
    $blocks += $current

    # Normalize group comment location:
    foreach ($b in $blocks) {
        if ($b.Type -ne 'host') { continue }

        $group = $null
        # 1) header lines (older style): look for group comment there
        for ($j = 0; $j -lt $b.HeaderLines.Count; $j++) {
            $h = $b.HeaderLines[$j]
            if ($h.Trim() -match $groupPattern) {
                $group = $Matches[1].Trim()
                break
            }
        }
        if ($group) {
            # remove any header lines that are group comments
            $b.HeaderLines = $b.HeaderLines | Where-Object { -not ($_.Trim() -match $groupPattern) }
            $b.Group = $group
            Add-RecentGroup -groupName $group
            continue
        }

        # 2) new style: check first line of Lines for an indented group comment
        if ($b.Lines.Count -gt 0) {
            $firstLine = $b.Lines[0]
            $linePattern = '^\s*' + $EscapedGroupPrefix + '\s*(.+)$'
            if ($firstLine -match $linePattern) {
                $group = $Matches[1].Trim()
                # remove the first line from Lines
                if ($b.Lines.Count -eq 1) {
                    $b.Lines = @()
                } else {
                    $b.Lines = $b.Lines[1..($b.Lines.Count-1)]
                }
                $b.Group = $group
                Add-RecentGroup -groupName $group
            }
        }
    }

    return $blocks
}

function Write-SSHConfigFromBlocks {
    param([array]$blocks)
    Backup-Config
    $out = @()
    foreach ($block in $blocks) {
        foreach ($header in $block.HeaderLines) { $out += $header }
        foreach ($line in $block.Lines) { $out += $line }
    }
    $content = ($out -join [Environment]::NewLine) + [Environment]::NewLine
    
    try {
        Set-Content -Path $SshConfigPath -Value $content -Encoding utf8 -ErrorAction Stop
        $Global:HasUnsavedChanges = $false
    } catch {
        [System.Windows.MessageBox]::Show("Failed to write SSH config: $($_.Exception.Message)","Write Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
    }
    
    UpdateUndoStatus
}

# ----------------------------
# === UI-friendly objects and block update logic
# ----------------------------
function Get-HostObjectsFromBlocks {
    param([array]$blocks)
    $list = @()
    for ($i=0; $i -lt $blocks.Count; $i++) {
        $block = $blocks[$i]
        if ($block.Type -ne 'host') { continue }
        
        $hostName = ($block.Lines | Where-Object { $_ -match '^(?i)\s*HostName\s+(.+)$' } | ForEach-Object { $Matches[1].Trim() }) | Select-Object -First 1
        $user = ($block.Lines | Where-Object { $_ -match '^(?i)\s*User\s+(.+)$' } | ForEach-Object { $Matches[1].Trim() }) | Select-Object -First 1
        $port = ($block.Lines | Where-Object { $_ -match '^(?i)\s*Port\s+(.+)$' } | ForEach-Object { $Matches[1].Trim() }) | Select-Object -First 1
        # Exclude group comment line (which we store in Lines as first line) from Additional
        $additionalLines = $block.Lines | Where-Object { -not ($_ -match '^\s*' + [regex]::Escape($GroupPrefix) + '\s*') } | Where-Object { -not ($_ -match '^(?i)\s*(HostName|User|Port)\s+') }
        $additionalText = ($additionalLines -join [Environment]::NewLine)
        
        $obj = [pscustomobject]@{
            Pattern = ($block.HostPatterns -join ',')
            HostName = if ($hostName) { [string]$hostName } else { '' }
            User = if ($user) { [string]$user } else { '' }
            Port = if ($port) { [string]$port } else { '' }
            Additional = if ($additionalText) { [string]$additionalText } else { '' }
            Group = if ($block.Group) { [string]$block.Group } else { '' }
            BlockIndex = $i
        }
        $list += $obj
    }
    return $list
}

function UpdateBlockFromItem {
    param($item)
    $idx = [int]$item.BlockIndex
    if ($idx -lt 0 -or $idx -ge $Global:Blocks.Count) { return }
    $block = $Global:Blocks[$idx]

    # Host patterns
    $newPatterns = ($item.Pattern -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    if ($newPatterns.Count -gt 0) {
        $block.HostPatterns = $newPatterns
        $hostLine = "Host " + ($newPatterns -join ' ')
        $foundHost = $false
        for ($headerIndex=0; $headerIndex -lt $block.HeaderLines.Count; $headerIndex++) {
            if ($block.HeaderLines[$headerIndex].Trim() -match '^(?i)Host\s+(.+)$') { 
                $block.HeaderLines[$headerIndex] = $hostLine
                $foundHost = $true
                break 
            }
        }
        if (-not $foundHost) {
            # keep any non-group header comments before the host line
            $rest = @()
            foreach ($header in $block.HeaderLines) {
                if ($header.Trim() -match '^' + $EscapedGroupPrefix + '\s*(.+)$') { 
                    # skip group comments (we will store them in Lines instead)
                } else { 
                    $rest += $header 
                }
            }
            $block.HeaderLines = ,$hostLine + $rest
        }
    }

    # Build new Lines (Group comment [as first indented line] + HostName/User/Port + Additional)
    $newLeading = @()
    if ($item.HostName -and $item.HostName.Trim() -ne '') { 
        $newLeading += "    HostName $($item.HostName.Trim())" 
    }
    if ($item.User -and $item.User.Trim() -ne '') { 
        $newLeading += "    User $($item.User.Trim())" 
    }
    if ($item.Port -and $item.Port.Trim() -ne '') { 
        $newLeading += "    Port $($item.Port.Trim())" 
    }

    if ($item.Additional -eq '') {
        $additionalLines = @()
    } else {
        $additionalLines = [System.Text.RegularExpressions.Regex]::Split($item.Additional, "`r?`n")
    }

    # Insert group comment as first indented line (after Host header)
    if ($item.Group -and $item.Group.Trim() -ne '') {
        $groupLine = "    $GroupPrefix $($item.Group.Trim())"
        $block.Group = $item.Group.Trim()
        Add-RecentGroup -groupName $block.Group
        $block.Lines = ,$groupLine + $newLeading + $additionalLines
    } else {
        $block.Group = $null
        $block.Lines = $newLeading + $additionalLines
    }

    $Global:Blocks[$idx] = $block
}

function Check-DuplicatePattern {
    param([string]$pattern, [int]$excludeIndex = -1)
    for ($i = 0; $i -lt $Global:Blocks.Count; $i++) {
        if ($i -eq $excludeIndex) { continue }
        $block = $Global:Blocks[$i]
        if ($block.Type -eq 'host' -and $block.HostPatterns -contains $pattern) {
            return $true
        }
    }
    return $false
}

# ----------------------------
# === SSH / WinSCP launch helpers
# ----------------------------
function Build-SshTarget {
    param($item)
    $hostValue = if ($item.HostName -and $item.HostName.Trim() -ne '') { 
        $item.HostName.Trim() 
    } else { 
        ($item.Pattern.Split(',')[0]).Trim() 
    }
    $target = if ($item.User -and $item.User.Trim() -ne '') { 
        "$($item.User.Trim())@$hostValue" 
    } else { 
        $hostValue 
    }
    $opts = @()
    if ($item.Port -and $item.Port.Trim() -ne '') { 
        $opts += "-p $($item.Port.Trim())" 
    }
    return @{ Target = $target; Options = ($opts -join ' ') }
}

function Launch-WT-WithItems {
    param([array]$items, [string]$split='vertical')
    if (-not $items -or $items.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("No hosts selected","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
        return 
    }
    
    # Build command segments for wt.exe
    $parts = @()
    $first = $items[0]
    $ssh = Build-SshTarget -item $first
    $opts = if ($ssh.Options -and $ssh.Options.Trim()) { " " + $ssh.Options.Trim() } else { "" }
    $sshCmd = "ssh " + $ssh.Target + $opts

    # Profile segment if requested
    $profileSegment = ""
    if ($Settings.WTProfile -and $Settings.WTProfile.Trim() -ne "") {
        $escapedProfile = $Settings.WTProfile.Replace('"','\"')
        $profileSegment = ' -p "' + $escapedProfile + '"'
    }

    # Create the new tab and run ssh directly (no shell wrapper)
    $parts += "new-tab" + $profileSegment + " -- " + $sshCmd

    # Add split panes for additional entries
    for ($i = 1; $i -lt $items.Count; $i++) {
        $record = $items[$i]
        $ssh = Build-SshTarget -item $record
        $opts = if ($ssh.Options -and $ssh.Options.Trim()) { " " + $ssh.Options.Trim() } else { "" }
        $sshCmd = "ssh " + $ssh.Target + $opts

        if ($split -match '^(?i)horizontal$') {
            $parts += ' ; split-pane -H -- ' + $sshCmd
        } else {
            $parts += ' ; split-pane -- ' + $sshCmd
        }
    }

    $cmdLine = ($parts -join '')

    # Attach to existing window if enabled (target most recent)
    $arg = $cmdLine
    if ($Settings.WTAttachToExistingWindow) {
        $arg = '-w 0 ' + $cmdLine
    }

    try {
        Start-Process -FilePath $Settings.WTPath -ArgumentList $arg -ErrorAction Stop
    } catch {
        # If attaching failed (maybe -w unsupported), retry without -w
        if ($Settings.WTAttachToExistingWindow) {
            try {
                Start-Process -FilePath $Settings.WTPath -ArgumentList $cmdLine -ErrorAction Stop
            } catch {
                [System.Windows.MessageBox]::Show("Could not launch Windows Terminal ($($Settings.WTPath)). Ensure it's installed and in PATH.","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
            }
        } else {
            [System.Windows.MessageBox]::Show("Could not launch Windows Terminal ($($Settings.WTPath)). Ensure it's installed and in PATH.","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
        }
    }
}

function Get-WinSCPPath {
    # 1) explicit
    if ($Settings.WinSCPPath -and $Settings.WinSCPPath.Trim() -ne "") {
        $explicit = [Environment]::ExpandEnvironmentVariables($Settings.WinSCPPath)
        if (Test-Path $explicit) { return $explicit }
    }
    # 2) candidates
    foreach ($path in $Settings.WinSCPCandidates) {
        $candidate = [Environment]::ExpandEnvironmentVariables($path)
        if (Test-Path $candidate) { return $candidate }
    }
    # 3) registry fallback
    try {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like "WinSCP*" } | Select-Object -First 1
        if ($reg -and $reg.InstallLocation) {
            $guess = Join-Path $reg.InstallLocation "WinSCP.exe"
            if (Test-Path $guess) { return $guess }
        }
    } catch {}
    return $null
}

# Append an extra SSH pane to the current Terminal window if possible
function Launch-WT-SplitSingle {
    param($item, [string]$split='vertical')

    if ($null -eq $item) { return }

    # Build ssh command
    $ssh = Build-SshTarget -item $item
    $opts = if ($ssh.Options -and $ssh.Options.Trim()) { " " + $ssh.Options.Trim() } else { "" }
    $sshCmd = "ssh " + $ssh.Target + $opts

    # Determine split flags
    $splitFlag = ""
    if ($split -match '^(?i)horizontal$') { $splitFlag = "-H" }

    # Try to split in the most recent WT window/tab
    $arg = "-w 0 split-pane $splitFlag -- " + $sshCmd

    try {
        Start-Process -FilePath $Settings.WTPath -ArgumentList $arg -ErrorAction Stop
        return
    } catch {
        # Fallback: if split failed, try creating a new tab instead (ensures the ssh still opens)
        try {
            Launch-WT-WithItems -items @($item) -split $split
            return
        } catch {
            [System.Windows.MessageBox]::Show("Could not launch Windows Terminal ($($Settings.WTPath)). Ensure it's installed and in PATH.","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
            return
        }
    }
}

function Launch-WinSCP-ForItem {
    param($item)
    $winscp = Get-WinSCPPath
    if (-not $winscp) { 
        [System.Windows.MessageBox]::Show("WinSCP not found on this machine.","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
        return 
    }
    
    $hostValue = if ($item.HostName -and $item.HostName.Trim() -ne '') { 
        $item.HostName.Trim() 
    } else { 
        ($item.Pattern.Split(',')[0]).Trim() 
    }
    $user = $item.User
    $port = $item.Port
    $proto = 'sftp'
    
    if ($user -and $user.Trim() -ne '') { 
        $url = "${proto}://${user.Trim()}@${hostValue}" 
    } else { 
        $url = "${proto}://${hostValue}" 
    }
    
    if ($port -and $port.Trim() -ne '') { 
        $url = $url + ":" + $port.Trim() + "/" 
    } else { 
        $url = $url + "/" 
    }
    
    Start-Process -FilePath $winscp -ArgumentList $url
}

# ----------------------------
# === XAML UI (per-field Apply checkboxes) with WT settings controls
#    NOTE: top toolbar replaced with WrapPanel so buttons wrap into multiple rows
# ----------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SSH Config Manager (Inline Edit)" Height="700" Width="800" WindowStartupLocation="CenterScreen">
  <DockPanel LastChildFill="True" Margin="6">
    <!-- Top toolbar -->
    <WrapPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,6" VerticalAlignment="Center">
	  <WrapPanel.Resources>
		<Style TargetType="Button">
		  <Setter Property="Margin" Value="0,0,6,6"/>
		</Style>
		<Style TargetType="TextBox">
		  <Setter Property="Margin" Value="0,0,6,6"/>
		</Style>
		<Style TargetType="StackPanel">
		  <Setter Property="Margin" Value="8,0,6,6"/>
		</Style>
	  </WrapPanel.Resources>

	  <TextBox x:Name="SearchBox" Width="140" MaxLength="50" VerticalAlignment="Center" />
	  <Button x:Name="BtnSearch" Width="80">Search</Button>
	  <Button x:Name="BtnNew" Width="100">New (Ctrl+N)</Button>
	  <Button x:Name="BtnApply" Width="110">Apply Edits (Ctrl+E)</Button>
	  <Button x:Name="BtnGroup" Width="90">Group (Ctrl+G)</Button>
	  <Button x:Name="BtnDelete" Width="100">Delete (Del)</Button>
	  <Button x:Name="BtnSSH" Width="100">Open SSH (Ctrl+O)</Button>
	  <Button x:Name="BtnWscp" Width="100">WinSCP (Ctrl+W)</Button>
	  <Button x:Name="BtnSave" Width="110">Save Config (Ctrl+S)</Button>
      <Button x:Name="BtnReload" Width="130">Reload Config (Ctrl+R)</Button>

	  <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="8,0,6,0">
		<CheckBox x:Name="ChkWTAttach" VerticalAlignment="Center" Margin="0,0,6,0" />
		<TextBlock VerticalAlignment="Center" Margin="0,0,6,0">Attach WT</TextBlock>
		<TextBlock VerticalAlignment="Center" Margin="0,0,6,0">Profile:</TextBlock>
		<TextBox x:Name="TxtWTProfile" Width="140" Margin="4,0,6,0" />
		<Button x:Name="BtnSaveWTSettings" Width="120">Save WT Settings</Button>
	  </StackPanel>

	  <Button x:Name="BtnExit" Width="70">Exit (Ctrl+Q)</Button>
	</WrapPanel>

    <!-- StatusBar MUST be docked before the Grid for proper layering -->
    <StatusBar DockPanel.Dock="Bottom" Height="24" Margin="0,6,0,0">
      <StatusBarItem>
        <TextBlock x:Name="StatusText">Ready</TextBlock>
      </StatusBarItem>
    </StatusBar>

    <!-- Grid now fills remaining space without overlapping StatusBar -->
    <Grid Margin="0,0,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="3*" MinWidth="360" />
        <ColumnDefinition Width="2*" MinWidth="300" />
      </Grid.ColumnDefinitions>

      <DataGrid x:Name="DataGrid" Grid.Column="0" AutoGenerateColumns="False" CanUserAddRows="False"
                SelectionMode="Extended" SelectionUnit="FullRow" Margin="0,0,6,0" IsReadOnly="True"
                ColumnWidth="*" ScrollViewer.HorizontalScrollBarVisibility="Auto">
        <DataGrid.Columns>
          <DataGridTextColumn Header="Nickname" Binding="{Binding Pattern}" Width="1*" MinWidth="80" />
          <DataGridTextColumn Header="HostName" Binding="{Binding HostName}" Width="1.3*" MinWidth="120" />
          <DataGridTextColumn Header="User" Binding="{Binding User}" Width="0.6*" MinWidth="60" />
          <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="0.4*" MinWidth="40" />
          <DataGridTextColumn Header="Group" Binding="{Binding Group}" Width="0.6*" MinWidth="70" />
        </DataGrid.Columns>
      </DataGrid>

      <Border Grid.Column="1" BorderBrush="LightGray" BorderThickness="1" Padding="8">
        <StackPanel>
          <TextBlock Text="Host Details (edit to apply to selected)" FontWeight="Bold" Margin="0,0,0,6"/>

          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <CheckBox x:Name="ChkPattern" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBlock Width="70" VerticalAlignment="Center">Nickname:</TextBlock>
            <TextBox x:Name="FldPattern" Width="180" />
          </StackPanel>

          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <CheckBox x:Name="ChkHostName" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBlock Width="70" VerticalAlignment="Center">HostName:</TextBlock>
            <TextBox x:Name="FldHostName" Width="180" />
          </StackPanel>

          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <CheckBox x:Name="ChkUser" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBlock Width="70" VerticalAlignment="Center">User:</TextBlock>
            <TextBox x:Name="FldUser" Width="180" />
          </StackPanel>

          <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
            <CheckBox x:Name="ChkPort" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBlock Width="70" VerticalAlignment="Center">Port:</TextBlock>
            <TextBox x:Name="FldPort" Width="80" />
          </StackPanel>

          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <CheckBox x:Name="ChkGroup" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <TextBlock Width="70" VerticalAlignment="Center">Group:</TextBlock>
            <TextBox x:Name="FldGroup" Width="180" />
          </StackPanel>

          <TextBlock Text="Additional lines (multi-line):" FontWeight="Bold" Margin="0,6,0,2"/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
            <CheckBox x:Name="ChkAdditional" VerticalAlignment="Top" Margin="0,4,6,0"/>
            <TextBox x:Name="FldAdditional" AcceptsReturn="True" Height="150" VerticalScrollBarVisibility="Auto" TextWrapping="Wrap" Width="250" />
          </StackPanel>

          <WrapPanel Margin="0,6,0,6">
            <Button x:Name="BtnApplyEdits" Width="110" Margin="0,0,6,0">Apply Edits (Ctrl+E)</Button>
            <Button x:Name="BtnEditRaw" Width="90" Margin="0,0,6,0">Edit Raw (ext)</Button>
            <Button x:Name="BtnRefresh" Width="80">Refresh List</Button>
          </WrapPanel>

          <TextBlock Text="Tips:" FontWeight="Bold" Margin="0,10,0,4"/>
          <TextBlock TextWrapping="Wrap">
			Select multiple rows with Ctrl/Shift. 
			<LineBreak/>
			Shift+Alt+double-click also opens terminal pane for each selection 
			<LineBreak/>
			Alt+double-click to add host as new pane
			<LineBreak/>
			Attach WT: Uses most recent Windows Terminal
			<LineBreak/>
			Profile: Specify Terminal profile for SSH connections
			<LineBreak/>
			To make changes permanent, select "Save Config (Ctrl+S)"
		  </TextBlock>
        </StackPanel>
      </Border>
    </Grid>
  </DockPanel>
</Window>
"@

# ----------------------------
# === Load XAML and find controls
# ----------------------------
try {
    $xmlDoc = New-Object System.Xml.XmlDocument
    $xmlDoc.LoadXml($xaml)
    $reader = New-Object System.Xml.XmlNodeReader($xmlDoc)
    $Window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Error "Failed to load XAML: $($_.Exception.Message)"
    throw
}

# Controls
$SearchBox = $Window.FindName('SearchBox')
$BtnSearch = $Window.FindName('BtnSearch')
$BtnNew = $Window.FindName('BtnNew')
$BtnApply = $Window.FindName('BtnApply')
$BtnGroup = $Window.FindName('BtnGroup')
$BtnDelete = $Window.FindName('BtnDelete')
$BtnSSH = $Window.FindName('BtnSSH')
$BtnWscp = $Window.FindName('BtnWscp')
$BtnSave = $Window.FindName('BtnSave')
$BtnReload = $Window.FindName('BtnReload')
$BtnExit = $Window.FindName('BtnExit')
$DataGrid = $Window.FindName('DataGrid')
$FldPattern = $Window.FindName('FldPattern')
$FldHostName = $Window.FindName('FldHostName')
$FldUser = $Window.FindName('FldUser')
$FldPort = $Window.FindName('FldPort')
$FldGroup = $Window.FindName('FldGroup')
$FldAdditional = $Window.FindName('FldAdditional')
$ChkPattern = $Window.FindName('ChkPattern')
$ChkHostName = $Window.FindName('ChkHostName')
$ChkUser = $Window.FindName('ChkUser')
$ChkPort = $Window.FindName('ChkPort')
$ChkGroup = $Window.FindName('ChkGroup')
$ChkAdditional = $Window.FindName('ChkAdditional')
$BtnApplyEdits = $Window.FindName('BtnApplyEdits')
$BtnEditRaw = $Window.FindName('BtnEditRaw')
$BtnRefresh = $Window.FindName('BtnRefresh')
$StatusText = $Window.FindName('StatusText')

# WT settings controls
$ChkWTAttach = $Window.FindName('ChkWTAttach')
$TxtWTProfile = $Window.FindName('TxtWTProfile')
$BtnSaveWTSettings = $Window.FindName('BtnSaveWTSettings')

# ----------------------------
# === State and population
# ----------------------------
$Global:Blocks = Parse-SSHConfig
$Global:Observable = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$Window.Dispatcher.Invoke([action]{ $DataGrid.ItemsSource = $Global:Observable })

function Refresh-List {
    param($filter)
    $all = Get-HostObjectsFromBlocks -blocks $Global:Blocks
    if ($filter -and $filter.Trim() -ne '') {
        $pattern = $filter
        $filtered = $all | Where-Object {
            ($_.Pattern -match $pattern) -or ($_.HostName -and $_.HostName -match $pattern) -or ($_.Group -and $_.Group -match $pattern)
        }
    } else { 
        $filtered = $all 
    }
    
    $Window.Dispatcher.Invoke([action]{
        $Global:Observable.Clear()
        foreach ($record in $filtered) { $Global:Observable.Add($record) }
        if ($Global:Observable.Count -gt 0) { $DataGrid.SelectedIndex = 0 }
        
        # Update status with counts
        $totalCount = $all.Count
        $filteredCount = $filtered.Count
        if ($filter -and $filter.Trim() -ne '') {
            $StatusText.Text = "Showing $filteredCount of $totalCount hosts"
        } else {
            $StatusText.Text = "Total: $totalCount hosts"
        }
        UpdateUndoStatus
    })
}

# Initial populate and status update
Refresh-List -filter ''
UpdateUndoStatus

# Initialize WT settings UI values from $Settings
try {
    if ($ChkWTAttach -ne $null) { $ChkWTAttach.IsChecked = [bool]$Settings.WTAttachToExistingWindow }
    if ($TxtWTProfile -ne $null) { $TxtWTProfile.Text = [string]$Settings.WTProfile }
} catch {}

# ----------------------------
# === Utility: common value for multi-selection
# ----------------------------
function Get-CommonValue {
    param($items,[string]$prop)
    if (-not $items -or $items.Count -eq 0) { return $null }
    $first = [string]($items[0].PSObject.Properties[$prop].Value)
    for ($i=1; $i -lt $items.Count; $i++) {
        $val = [string]($items[$i].PSObject.Properties[$prop].Value)
        if ($val -ne $first) { return $null }
    }
    return $first
}

# ----------------------------
# === UI Event Handlers
# ----------------------------

# Save WT settings button
if ($BtnSaveWTSettings -ne $null) {
    $BtnSaveWTSettings.Add_Click({
        try {
            $Settings.WTAttachToExistingWindow = [bool]($ChkWTAttach.IsChecked -eq $true)
            $Settings.WTProfile = if ($TxtWTProfile.Text) { $TxtWTProfile.Text.Trim() } else { "" }
            Save-Settings
            $StatusText.Text = "Windows Terminal settings saved."
        } catch {
            [System.Windows.MessageBox]::Show("Failed to save WT settings: $($_.Exception.Message)","Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
        }
    })
}

# Real-time search as user types
$SearchBox.Add_TextChanged({
    Refresh-List -filter $SearchBox.Text
})

$DataGrid.Add_SelectionChanged({
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    
    if ($selItems.Count -eq 0) {
        $FldPattern.Text = ''
        $FldHostName.Text = ''
        $FldUser.Text = ''
        $FldPort.Text = ''
        $FldGroup.Text = ''
        $FldAdditional.Text = ''
        $ChkPattern.IsChecked = $false
        $ChkHostName.IsChecked = $false
        $ChkUser.IsChecked = $false
        $ChkPort.IsChecked = $false
        $ChkGroup.IsChecked = $false
        $ChkAdditional.IsChecked = $false
        $StatusText.Text = "No selection"
        return
    } elseif ($selItems.Count -eq 1) {
        $it = $selItems[0]
        $FldPattern.Text = [string]$it.Pattern
        $FldHostName.Text = [string]$it.HostName
        $FldUser.Text = [string]$it.User
        $FldPort.Text = [string]$it.Port
        $FldGroup.Text = [string]$it.Group
        $FldAdditional.Text = [string]$it.Additional
        # defaults: single selection -> all checked
        $ChkPattern.IsChecked = $true
        $ChkHostName.IsChecked = $true
        $ChkUser.IsChecked = $true
        $ChkPort.IsChecked = $true
        $ChkGroup.IsChecked = $true
        $ChkAdditional.IsChecked = $true
        $StatusText.Text = "Selected: $($it.Pattern)"
    } else {
        $commonPattern = Get-CommonValue -items $selItems -prop 'Pattern'
        $commonHostName = Get-CommonValue -items $selItems -prop 'HostName'
        $commonUser = Get-CommonValue -items $selItems -prop 'User'
        $commonPort = Get-CommonValue -items $selItems -prop 'Port'
        $commonGroup = Get-CommonValue -items $selItems -prop 'Group'
        $commonAdditional = Get-CommonValue -items $selItems -prop 'Additional'

        if ($commonPattern -ne $null -and $commonPattern -ne '') { 
            $FldPattern.Text = $commonPattern
            $ChkPattern.IsChecked = $true 
        } else { 
            $FldPattern.Text = ''
            $ChkPattern.IsChecked = $false 
        }
        
        if ($commonHostName -ne $null -and $commonHostName -ne '') { 
            $FldHostName.Text = $commonHostName
            $ChkHostName.IsChecked = $true 
        } else { 
            $FldHostName.Text = ''
            $ChkHostName.IsChecked = $false 
        }
        
        if ($commonUser -ne $null -and $commonUser -ne '') { 
            $FldUser.Text = $commonUser
            $ChkUser.IsChecked = $true 
        } else { 
            $FldUser.Text = ''
            $ChkUser.IsChecked = $false 
        }
        
        if ($commonPort -ne $null -and $commonPort -ne '') { 
            $FldPort.Text = $commonPort
            $ChkPort.IsChecked = $true 
        } else { 
            $FldPort.Text = ''
            $ChkPort.IsChecked = $false 
        }
        
        if ($commonGroup -ne $null -and $commonGroup -ne '') { 
            $FldGroup.Text = $commonGroup
            $ChkGroup.IsChecked = $true 
        } else { 
            $FldGroup.Text = ''
            $ChkGroup.IsChecked = $false 
        }
        
        if ($commonAdditional -ne $null -and $commonAdditional -ne '') { 
            $FldAdditional.Text = $commonAdditional
            $ChkAdditional.IsChecked = $true 
        } else { 
            $FldAdditional.Text = ''
            $ChkAdditional.IsChecked = $false 
        }

        $StatusText.Text = "Multiple selected: $($selItems.Count) rows"
    }
})

# Apply edits with validation
$applyAction = {
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    if ($selItems.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("No selection to apply edits.","Info")
        return 
    }
    
    # Validation
    if ($ChkPattern.IsChecked -and [string]::IsNullOrWhiteSpace($FldPattern.Text)) {
        [System.Windows.MessageBox]::Show("Nickname cannot be empty.","Validation Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    if ($ChkPort.IsChecked -and -not (Validate-Port -port $FldPort.Text)) {
        [System.Windows.MessageBox]::Show("Port must be between 1 and 65535.","Validation Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    # Check for duplicate patterns when editing single host
    if ($selItems.Count -eq 1 -and $ChkPattern.IsChecked) {
        $newPattern = $FldPattern.Text.Trim().Split(',')[0].Trim()
        if (Check-DuplicatePattern -pattern $newPattern -excludeIndex $selItems[0].BlockIndex) {
            $result = [System.Windows.MessageBox]::Show("A host with nickname '$newPattern' already exists. Continue anyway?","Duplicate Host",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
            if ($result -eq 'No') { return }
        }
    }
    
    PushUndo "Apply edits to $($selItems.Count) host(s)"
    
    foreach ($it in $selItems) {
        if ($ChkPattern.IsChecked) { $it.Pattern = $FldPattern.Text }
        if ($ChkHostName.IsChecked) { $it.HostName = $FldHostName.Text }
        if ($ChkUser.IsChecked) { $it.User = $FldUser.Text }
        if ($ChkPort.IsChecked) { $it.Port = $FldPort.Text }
        if ($ChkGroup.IsChecked) { $it.Group = $FldGroup.Text }
        if ($ChkAdditional.IsChecked) { $it.Additional = $FldAdditional.Text }
        UpdateBlockFromItem -item $it
    }
    
    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Applied edits to $($selItems.Count) host(s) (in memory)."
}
$BtnApplyEdits.Add_Click($applyAction)
$BtnApply.Add_Click($applyAction)

# Delete selected hosts with confirmation
$BtnDelete.Add_Click({
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    
    if ($selItems.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("No hosts selected to delete.","Info")
        return 
    }
    
    $hostNames = ($selItems | ForEach-Object { $_.Pattern }) -join ', '
    $message = if ($selItems.Count -eq 1) {
        "Delete host '$hostNames'?"
    } else {
        "Delete $($selItems.Count) hosts?`n`n$hostNames"
    }
    
    $result = [System.Windows.MessageBox]::Show($message,"Confirm Delete",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Question)
    
    if ($result -eq 'Yes') {
        PushUndo "Delete $($selItems.Count) host(s)"
        
        # Get indices to delete (in reverse order to avoid index shifting)
        $indices = ($selItems | ForEach-Object { $_.BlockIndex } | Sort-Object -Descending)
        
        foreach ($idx in $indices) {
            $Global:Blocks = $Global:Blocks[0..($idx-1)] + $Global:Blocks[($idx+1)..($Global:Blocks.Count-1)]
        }
        
        Refresh-List -filter $SearchBox.Text
        $StatusText.Text = "Deleted $($selItems.Count) host(s) (in memory)."
    }
})

# Raw external edit with undo
$BtnEditRaw.Add_Click({
    $sel = $DataGrid.SelectedItem
    if ($null -eq $sel) { 
        [System.Windows.MessageBox]::Show("Select a host to edit raw.","Info")
        return 
    }
    
    PushUndo "Raw edit for $($sel.Pattern)"
    $idx = $sel.BlockIndex
    $block = $Global:Blocks[$idx]
    $tmp = [System.IO.Path]::GetTempFileName() + ".sshedit"
    
    $buf = @()
    foreach ($header in $block.HeaderLines) { $buf += $header }
    foreach ($line in $block.Lines) { $buf += $line }
    Set-Content -Path $tmp -Value ($buf -join [Environment]::NewLine) -Encoding utf8

    $editorCmd = $Settings.Editor
    $parts = $editorCmd -split '\s+'
    $exe = $parts[0]
    $args = @()
    if ($parts.Count -gt 1) { $args += $parts[1..($parts.Count-1)] }
    $args += $tmp
    
    try { 
        Start-Process -FilePath $exe -ArgumentList $args -Wait -ErrorAction Stop 
    } catch { 
        & $exe $args 
    }

    $edited = Get-Content -Path $tmp -Raw -ErrorAction SilentlyContinue
    if (-not $edited) { 
        $StatusText.Text = "Raw edit cancelled"
        return 
    }
    
    $arr = [System.Text.RegularExpressions.Regex]::Split($edited, "`r?`n")
    $hostLineIndex = -1
    

	for ($i=0; $i -lt $arr.Length; $i++) {
		if ($arr[$i].Trim() -match '^(?i)Host\s+(.+)$') {
			$hostLineIndex = $i
			break
		}
	}

    
    if ($hostLineIndex -eq -1) { 
        [System.Windows.MessageBox]::Show("Edited block must contain a Host line. Aborting.","Error")
        return 
    }
    
    $newHeader = $arr[0..$hostLineIndex]
    $newLines = if ($hostLineIndex + 1 -lt $arr.Length) { 
        $arr[($hostLineIndex+1)..($arr.Length-1)] 
    } else { 
        @() 
    }
    
    $hostLine = $arr[$hostLineIndex].Trim()
	$hostLine -match '^(?i)Host\s+(.+)$' | Out-Null
    $newPatterns = $Matches[1].Trim().Split() | Where-Object { $_ -ne '' }
    
    # --- Normalize group extracted either from header or from first line of newLines ---
    $group = $null
    $groupPattern = '^' + $EscapedGroupPrefix + '\s*(.+)$'

    # Check header (legacy placement)
    for ($j=0; $j -lt $newHeader.Length; $j++) {
        if ($newHeader[$j].Trim() -match $groupPattern) {
            $group = $Matches[1].Trim()
            # remove any group comment lines from header
            $newHeader = $newHeader | Where-Object { -not ($_.Trim() -match $groupPattern) }
            break
        }
    }

    # If not found in header, check first line of newLines (new style): optional leading whitespace allowed
    if (-not $group -and $newLines.Count -gt 0) {
        $first = $newLines[0]
        $linePattern = '^\s*' + $EscapedGroupPrefix + '\s*(.+)$'
        if ($first -match $linePattern) {
            $group = $Matches[1].Trim()
            # remove the first line from newLines
            if ($newLines.Count -eq 1) { $newLines = @() } else { $newLines = $newLines[1..($newLines.Count-1)] }
        }
    }

    $Global:Blocks[$idx].HeaderLines = $newHeader
    $Global:Blocks[$idx].Lines = $newLines
    $Global:Blocks[$idx].HostPatterns = $newPatterns
    $Global:Blocks[$idx].Group = $group
    if ($group) { Add-RecentGroup -groupName $group }

    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Raw edit applied (in memory)."
})

# Refresh from disk
$BtnRefresh.Add_Click({
    if ($Global:HasUnsavedChanges) {
        $result = [System.Windows.MessageBox]::Show("You have unsaved changes. Refreshing will discard them. Continue?","Unsaved Changes",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
        if ($result -eq 'No') { return }
    }
    
    $Global:Blocks = Parse-SSHConfig
    $Global:HasUnsavedChanges = $false
    $Global:UndoStack = @()
    $Global:RedoStack = @()
    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Refreshed from $SshConfigPath"
})

# New host dialog
function Show-CreateHostDialog {
    $dlgXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Create Host" Height="300" Width="420" WindowStartupLocation="CenterOwner" ResizeMode="NoResize">
  <Grid Margin="8">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions><ColumnDefinition Width="90"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>

    <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center">Nickname:</TextBlock>
    <TextBox Grid.Row="0" Grid.Column="1" x:Name="DlgPattern" Margin="0,4,0,4" />

    <TextBlock Grid.Row="1" Grid.Column="0" VerticalAlignment="Center">HostName:</TextBlock>
    <TextBox Grid.Row="1" Grid.Column="1" x:Name="DlgHostName" Margin="0,4,0,4" />

    <TextBlock Grid.Row="2" Grid.Column="0" VerticalAlignment="Center">User:</TextBlock>
    <TextBox Grid.Row="2" Grid.Column="1" x:Name="DlgUser" Margin="0,4,0,4" />

    <TextBlock Grid.Row="3" Grid.Column="0" VerticalAlignment="Center">Port:</TextBlock>
    <TextBox Grid.Row="3" Grid.Column="1" x:Name="DlgPort" Margin="0,4,0,4" />

    <TextBlock Grid.Row="4" Grid.Column="0" VerticalAlignment="Center">Group:</TextBlock>
    <TextBox Grid.Row="4" Grid.Column="1" x:Name="DlgGroup" Margin="0,4,0,4" />

    <StackPanel Grid.Row="5" Grid.ColumnSpan="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
      <Button x:Name="DlgOk" Width="80" Height="26" Margin="0,0,6,0">OK</Button>
      <Button x:Name="DlgCancel" Width="80" Height="26">Cancel</Button>
    </StackPanel>
  </Grid>
</Window>
"@

    try {
        $xmlDoc = New-Object System.Xml.XmlDocument
        $xmlDoc.LoadXml($dlgXaml)
        $reader = New-Object System.Xml.XmlNodeReader($xmlDoc)
        $dlg = [Windows.Markup.XamlReader]::Load($reader)
    } catch {
        return $null
    }

    $DlgPattern = $dlg.FindName('DlgPattern')
    $DlgHostName = $dlg.FindName('DlgHostName')
    $DlgUser = $dlg.FindName('DlgUser')
    $DlgPort = $dlg.FindName('DlgPort')
    $DlgGroup = $dlg.FindName('DlgGroup')
    $DlgOk = $dlg.FindName('DlgOk')
    $DlgCancel = $dlg.FindName('DlgCancel')

    $script:dialogResult = $null

    $DlgOk.Add_Click({
        if (-not $DlgPattern.Text.Trim()) {
            [System.Windows.MessageBox]::Show("Nickname is required.","Validation",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
            return
        }

        if ($DlgPort.Text.Trim() -and -not (Validate-Port -port $DlgPort.Text.Trim())) {
            [System.Windows.MessageBox]::Show("Port must be between 1 and 65535.","Validation",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning)
            return
        }

        $newPattern = $DlgPattern.Text.Trim()
        if (Check-DuplicatePattern -pattern $newPattern) {
            $dupResult = [System.Windows.MessageBox]::Show("A host with nickname '$newPattern' already exists. Create anyway?","Duplicate Host",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
            if ($dupResult -eq 'No') { return }
        }

        $script:dialogResult = [pscustomobject]@{
            Pattern = $DlgPattern.Text.Trim()
            HostName = $DlgHostName.Text.Trim()
            User = $DlgUser.Text.Trim()
            Port = $DlgPort.Text.Trim()
            Group = $DlgGroup.Text.Trim()
        }
        
        $dlg.DialogResult = $true
        $dlg.Close()
    })

    $DlgCancel.Add_Click({ 
        $dlg.DialogResult = $false
        $dlg.Close() 
    })

    try { $dlg.Owner = $Window } catch {}
    
    $dlg.ShowDialog() | Out-Null
    return $script:dialogResult
}

$BtnNew.Add_Click({
    $res = Show-CreateHostDialog
    if ($null -eq $res) {
        $StatusText.Text = "Create cancelled"
        return
    }

    PushUndo "Create host $($res.Pattern)"

    # Build host block: Host header + (optional) indented group comment + indented settings
    $header = @("Host " + $res.Pattern)
    $lines = @()
    
    if ($res.Group -and $res.Group.Trim() -ne '') {
        $lines += "    $GroupPrefix $($res.Group.Trim())"
    }
    if ($res.HostName) { $lines += "    HostName $($res.HostName)" }
    if ($res.User) { $lines += "    User $($res.User)" }
    if ($res.Port) { $lines += "    Port $($res.Port)" }
    
    $block = @{ 
        Type = 'host'
        HeaderLines = $header
        Lines = $lines
        HostPatterns = ($res.Pattern -split '\s+')
        Group = if ($res.Group -and $res.Group.Trim() -ne '') { $res.Group.Trim() } else { $null } 
    }
    
    # Insert host before trailing global block if present, otherwise append
    $count = $Global:Blocks.Count
    if ($count -gt 0 -and $Global:Blocks[$count - 1].Type -eq 'global') {
        $before = @()
        if ($count -gt 1) { $before = $Global:Blocks[0..($count - 2)] }
        $after = $Global:Blocks[$count - 1]
        $Global:Blocks = $before + ,$block + ,$after
    } else {
        $Global:Blocks += ,$block
    }

    # Refresh list with empty filter so the new entry is visible
    Refresh-List -filter ''
    
    # Select the newly-added item in the grid
    $Window.Dispatcher.Invoke([action]{
        $matchIndex = -1
        for ($i=0; $i -lt $Global:Observable.Count; $i++) {
            if ($Global:Observable[$i].Pattern -eq $res.Pattern) { 
                $matchIndex = $i
                break 
            }
        }
        if ($matchIndex -ge 0) {
            $DataGrid.SelectedIndex = $matchIndex
            $DataGrid.ScrollIntoView($DataGrid.SelectedItem)
        } else {
            $DataGrid.SelectedIndex = ($Global:Observable.Count - 1)
            if ($DataGrid.SelectedItem) {
                $DataGrid.ScrollIntoView($DataGrid.SelectedItem)
            }
        }
    })

    $StatusText.Text = "Created host $($res.Pattern) (in memory)."
})

# Group selected rows with recent groups
$BtnGroup.Add_Click({
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    
    if ($selItems.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("Select rows to tag/untag.","Info")
        return 
    }
    
    $input = [Microsoft.VisualBasic.Interaction]::InputBox("Enter group name (leave empty to remove):","Group hosts","")
    if ($null -eq $input) { return }
    
    PushUndo "Group update for $($selItems.Count) host(s)"
    
    foreach ($s in $selItems) {
        $s.Group = $input.Trim()
        UpdateBlockFromItem -item $s
    }
    
    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Group updated (in memory)."
})

# Open SSH for selected rows
$BtnSSH.Add_Click({
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    
    if ($selItems.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("Select rows to open SSH.","Info")
        return 
    }
    
    $resp = [Microsoft.VisualBasic.Interaction]::InputBox("Split direction: vertical or horizontal","Open SSH","vertical")
    if ($null -eq $resp) { return }
    
    Launch-WT-WithItems -items ($selItems) -split $resp
})

# WinSCP for single selection
$BtnWscp.Add_Click({
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }
    
    if ($selItems.Count -eq 0) { 
        [System.Windows.MessageBox]::Show("Select one row to open in WinSCP.","Info")
        return 
    }
    if ($selItems.Count -gt 1) { 
        [System.Windows.MessageBox]::Show("Select only one row for WinSCP.","Info")
        return 
    }
    
    Launch-WinSCP-ForItem -item $selItems[0]
})

# Save config with confirmation
$BtnSave.Add_Click({
    if (-not $Global:HasUnsavedChanges) {
        $result = [System.Windows.MessageBox]::Show("No unsaved changes. Save anyway?","Save",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Question)
        if ($result -eq 'No') { return }
    }
    
    # Final validation before save
    $hosts = Get-HostObjectsFromBlocks -blocks $Global:Blocks
    foreach ($record in $hosts) {
        if (-not (Validate-Port -port $record.Port)) {
            [System.Windows.MessageBox]::Show("Invalid port '$($record.Port)' for host '$($record.Pattern)'. Please fix before saving.","Validation Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
            return
        }
    }
    
    Write-SSHConfigFromBlocks -blocks $Global:Blocks
    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Saved to $SshConfigPath (backup created)."
})

# Reload config
$BtnReload.Add_Click({
    if ($Global:HasUnsavedChanges) {
        $result = [System.Windows.MessageBox]::Show("You have unsaved changes. Reloading will discard them. Continue?","Unsaved Changes",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
        if ($result -eq 'No') { return }
    }
    
    $Global:Blocks = Parse-SSHConfig
    $Global:HasUnsavedChanges = $false
    $Global:UndoStack = @()
    $Global:RedoStack = @()
    Refresh-List -filter $SearchBox.Text
    $StatusText.Text = "Reloaded from $SshConfigPath"
    UpdateUndoStatus
})

# Search
$BtnSearch.Add_Click({
    Refresh-List -filter $SearchBox.Text
})

# Exit with unsaved changes check
$BtnExit.Add_Click({
    if ($Global:HasUnsavedChanges) {
        $result = [System.Windows.MessageBox]::Show("You have unsaved changes. Exit anyway?","Unsaved Changes",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
        if ($result -eq 'No') { return }
    }
    $Window.Close()
})

# Keyboard hotkeys
$Window.Add_KeyDown({
    param($sender,$e)
    $mods = [System.Windows.Input.Keyboard]::Modifiers
    
    if ($mods -band [System.Windows.Input.ModifierKeys]::Control) {
        switch ($e.Key.ToString()) {
            'N' { $BtnNew.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'E' { $BtnApply.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'G' { $BtnGroup.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'O' { $BtnSSH.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'W' { $BtnWscp.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'S' { $BtnSave.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
            'R' { $BtnReload.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)); $e.Handled = $true }
			'F' { $SearchBox.Focus(); $e.Handled = $true }
            'Q' { $Window.Close(); $e.Handled = $true }
            'Z' { Undo; $e.Handled = $true }
            'Y' { Redo; $e.Handled = $true }
        }
    } else {
        if ($e.Key -eq 'Escape') { 
            $Window.Close()
            $e.Handled = $true 
        }
        if ($e.Key -eq 'Delete') {
            $BtnDelete.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
            $e.Handled = $true
        }
    }
})

# Replace your current DataGrid.Add_MouseDoubleClick handler with this:
$DataGrid.Add_MouseDoubleClick({
    param($sender, $e)

    # Collect all currently selected items (so double-click on one of several still uses the full selection)
    $selItems = @()
    foreach ($o in $DataGrid.SelectedItems) { $selItems += $o }

    if ($selItems.Count -eq 0) { return }

    # Use the first selected item to populate the details panel (as before)
    $item = $selItems[0]
    $FldPattern.Text = [string]$item.Pattern
    $FldHostName.Text = [string]$item.HostName
    $FldUser.Text = [string]$item.User
    $FldPort.Text = [string]$item.Port
    $FldGroup.Text = [string]$item.Group
    $FldAdditional.Text = [string]$item.Additional
    $ChkPattern.IsChecked = $true
    $ChkHostName.IsChecked = $true
    $ChkUser.IsChecked = $true
    $ChkPort.IsChecked = $true
    $ChkGroup.IsChecked = $true
    $ChkAdditional.IsChecked = $true

    $StatusText.Text = if ($selItems.Count -gt 1) { "Selected: $($selItems.Count) rows" } else { "Selected: $($item.Pattern)" }

    # Determine whether Alt is held at the time of the double-click
    $mods = [System.Windows.Input.Keyboard]::Modifiers
    $useSplit = ($mods -band [System.Windows.Input.ModifierKeys]::Alt)

    # Choose split direction (could be made configurable / detect Shift for horizontal)
    $splitDirection = 'vertical'

    try {
        if ($useSplit) {
            if ($selItems.Count -gt 1) {
                # Alt + multi-select: create one new tab and split panes for the selected items
                Launch-WT-WithItems -items $selItems -split $splitDirection
            } else {
                # Alt + single: attempt to split the active tab (no new tab)
                Launch-WT-SplitSingle -item $selItems[0] -split $splitDirection
            }
        } else {
            # Plain double-click: open single item in a new tab
            Launch-WT-WithItems -items @($item) -split $splitDirection
        }
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open SSH session: $($_.Exception.Message)","Launch Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error)
    }
})

# Window closing event
$Window.Add_Closing({
    param($sender, $e)
    if ($Global:HasUnsavedChanges) {
        $result = [System.Windows.MessageBox]::Show("You have unsaved changes. Exit anyway?","Unsaved Changes",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
        if ($result -eq 'No') { 
            $e.Cancel = $true 
        }
    }
})

# Show window
$Window.ShowDialog() | Out-Null
