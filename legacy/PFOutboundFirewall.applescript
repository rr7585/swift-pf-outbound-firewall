use framework "Cocoa"
use scripting additions

-- 脚本编辑器可能在后台线程执行脚本主体。
-- 继承 NSObject 后，可把整个界面入口安全地调度到 AppKit 主线程。
property parent : class "NSObject"

-- macOS PF 出站防火墙管理器（AppleScriptObjC / Cocoa）
-- 防护开启时仅允许 lo0、utun0～utun9 和白名单目的地址出站。
-- 主窗口使用正常的 AppKit 事件循环，菜单和窗口按钮通过 target/action 响应。

property appTitle : "PF 出站防火墙"
property dataDir : "/Library/Application Support/PFOutboundFirewall"
property allowlistFile : dataDir & "/allowlist.txt"
property rulesFile : dataDir & "/rules.conf"
property startupFile : dataDir & "/startup.sh"
property installMarker : dataDir & "/installed.ok"
property startupLog : dataDir & "/startup.log"
-- /var/run 会在重启后清空；开机任务会重新开启 PF，所以关闭标记不应跨重启保留。
property disabledPath : "/var/run/com.user.pf-outbound.disabled"
property systemPath : "/Library/LaunchDaemons/com.user.pf-outbound.plist"
property serviceID : "com.user.pf-outbound"
-- AppleScript 不允许在 property 声明中直接使用 missing value；首次显示界面时再初始化。
property allowlistView : ""
property managerWindow : ""
property managerResponse : 0
property editorHostMode : false

on shellQuote(theText)
	return quoted form of (theText as text)
end shellQuote

on adminRun(commandText)
	-- 使用 Standard Additions 的原始参数代码，避免部分系统的 osacompile
	-- 无法解析 “with administrator privileges” 术语。
	return do shell script commandText with administrator privileges
end adminRun

on isInstalled()
	try
		-- 只有开机脚本成功加载 PF 规则后才会生成 installed.ok。
		-- 上次安装中途失败时仍显示“未安装”，可直接再次安装完成修复。
		do shell script ("/bin/test -d " & my shellQuote(dataDir) & " && /bin/test -f " & my shellQuote(systemPath) & " && /bin/test -f " & my shellQuote(installMarker))
		return true
	on error
		return false
	end try
end isInstalled

on isProtected()
	if not my isInstalled() then return false
	try
		-- pfctl 状态查询需要 root，普通查询会因权限不足而误报“已关闭”。
		-- 默认安装状态为开启；只有本程序成功停用后才写入关闭标记。
		do shell script ("/bin/test ! -f " & my shellQuote(disabledPath))
		return true
	on error
		return false
	end try
end isProtected

on readAllowlist()
	try
		return do shell script ("/bin/cat " & my shellQuote(allowlistFile))
	on error
		return ""
	end try
end readAllowlist

on fixedRulesText(listPath)
	-- 先载入系统自带配置，避免用自定义规则直接替换 Apple 的主规则集。
	set ruleText to "table <vpn_allowlist> persist file \"" & listPath & "\"" & linefeed
	set ruleText to ruleText & "pass out quick on lo0 all" & linefeed
	repeat with interfaceNumber from 0 to 9
		set ruleText to ruleText & "pass out quick on utun" & interfaceNumber & " all" & linefeed
	end repeat
	set ruleText to ruleText & "pass out quick to <vpn_allowlist>" & linefeed
	set ruleText to ruleText & "block drop out quick all" & linefeed
	return ruleText
end fixedRulesText

-- macOS 偶尔会有其他系统服务短暂占用 PF 事务锁；短暂重试可避免 DIOCXCOMMIT: Resource busy。
on pfLoadCommand()
	return "attempt=0; until /sbin/pfctl -f " & my shellQuote(rulesFile) & "; do attempt=$((attempt + 1)); if [ \"$attempt\" -ge 10 ]; then exit 1; fi; /bin/sleep 0.2; done"
end pfLoadCommand

on saveAllowlist(shouldApply)
	set listText to (allowlistView's |string|()) as text
	set tempList to dataDir & "/allowlist.new"
	set tempRules to dataDir & "/rules.new"
	set validationRules to my fixedRulesText(tempList)
	set finalRules to my fixedRulesText(allowlistFile)
	set commandText to "set -e; /bin/mkdir -p " & my shellQuote(dataDir) & "; /bin/chmod 755 " & my shellQuote(dataDir) & "; /usr/bin/printf '%s' " & my shellQuote(listText) & " > " & my shellQuote(tempList) & "; /usr/bin/printf '%s' " & my shellQuote(validationRules) & " > " & my shellQuote(tempRules) & "; /sbin/pfctl -nf " & my shellQuote(tempRules) & " >/dev/null; /bin/mv " & my shellQuote(tempList) & " " & my shellQuote(allowlistFile) & "; /usr/bin/printf '%s' " & my shellQuote(finalRules) & " > " & my shellQuote(rulesFile) & "; /bin/rm -f " & my shellQuote(tempRules) & "; /bin/chmod 644 " & my shellQuote(allowlistFile) & "; /bin/chmod 600 " & my shellQuote(rulesFile)
	if shouldApply then set commandText to commandText & "; " & my pfLoadCommand() & "; /sbin/pfctl -F states"
	my adminRun(commandText)
end saveAllowlist

on installAndEnable()
	set initialRules to my fixedRulesText(allowlistFile)
	set scriptText to "#!/bin/sh" & linefeed & "exec > " & my shellQuote(startupLog) & " 2>&1" & linefeed & "set -e" & linefeed & "/bin/rm -f " & my shellQuote(installMarker) & linefeed & "/sbin/pfctl -nf " & my shellQuote(rulesFile) & linefeed & my pfLoadCommand() & linefeed & "if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -e; fi" & linefeed & "/sbin/pfctl -F states" & linefeed & "/bin/rm -f " & my shellQuote(disabledPath) & linefeed & "/usr/bin/touch " & my shellQuote(installMarker) & linefeed
	set plistText to "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" & linefeed & "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" & linefeed & "<plist version=\"1.0\"><dict>" & linefeed & "<key>Label</key><string>" & serviceID & "</string>" & linefeed & "<key>ProgramArguments</key><array><string>/bin/sh</string><string>" & startupFile & "</string></array>" & linefeed & "<key>RunAtLoad</key><true/>" & linefeed & "</dict></plist>" & linefeed
	-- bootstrap 的 RunAtLoad 已负责加载 PF，安装命令不能再并发执行第二次 pfctl -f。
	set commandText to "set -e; /bin/mkdir -p " & my shellQuote(dataDir) & "; /bin/chmod 755 " & my shellQuote(dataDir) & "; /bin/rm -f " & my shellQuote(installMarker) & "; /usr/bin/touch " & my shellQuote(allowlistFile) & "; /usr/bin/printf '%s' " & my shellQuote(initialRules) & " > " & my shellQuote(rulesFile) & "; /bin/chmod 644 " & my shellQuote(allowlistFile) & "; /bin/chmod 600 " & my shellQuote(rulesFile) & "; /usr/bin/printf '%s' " & my shellQuote(scriptText) & " > " & my shellQuote(startupFile) & "; /bin/chmod 700 " & my shellQuote(startupFile) & "; /usr/bin/printf '%s' " & my shellQuote(plistText) & " > " & my shellQuote(systemPath) & "; /bin/chmod 644 " & my shellQuote(systemPath) & "; /bin/launchctl bootout system/" & serviceID & " 2>/dev/null || true; /bin/launchctl bootstrap system " & my shellQuote(systemPath) & "; count=0; while [ ! -f " & my shellQuote(installMarker) & " ] && [ \"$count\" -lt 100 ]; do /bin/sleep 0.1; count=$((count + 1)); done; if [ ! -f " & my shellQuote(installMarker) & " ]; then /bin/cat " & my shellQuote(startupLog) & " >&2 2>/dev/null || true; exit 1; fi"
	my adminRun(commandText)
end installAndEnable

on uninstallFirewall()
	-- 不要写成 my handler(... my otherHandler(...) ...)；AppleScriptObjC
	-- 重新编译纯文本源码时可能把嵌套调用误判为 Cocoa 命令。
	set quotedDataDir to my shellQuote(dataDir)
	set quotedSystemPath to my shellQuote(systemPath)
	set commandText to "/bin/launchctl bootout system/" & serviceID & " 2>/dev/null || true; /sbin/pfctl -F all 2>/dev/null || true; /sbin/pfctl -d 2>/dev/null || true; /bin/rm -rf " & quotedDataDir & "; /bin/rm -f " & quotedSystemPath
	my adminRun(commandText)
end uninstallFirewall

on disableProtection()
	set quotedDisabledPath to my shellQuote(disabledPath)
	set commandText to "set -e; if /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -d; fi; /sbin/pfctl -F states; /usr/bin/touch " & quotedDisabledPath
	my adminRun(commandText)
end disableProtection

on enableProtection()
	my saveAllowlist(false)
	set loadCommand to my pfLoadCommand()
	set quotedDisabledPath to my shellQuote(disabledPath)
	set commandText to "set -e; " & loadCommand & "; if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -e; fi; /sbin/pfctl -F states; /bin/rm -f " & quotedDisabledPath
	my adminRun(commandText)
end enableProtection

on isScriptEditorHost()
	try
		set hostIdentifier to current application's NSBundle's mainBundle()'s bundleIdentifier()
		if hostIdentifier is missing value then return false
		set hostIdentifierText to hostIdentifier as text
		return hostIdentifierText is "com.apple.ScriptEditor2" or hostIdentifierText is "com.apple.ScriptEditor"
	on error
		return false
	end try
end isScriptEditorHost

on stopManagerModal(responseCode)
	set managerResponse to responseCode
	current application's NSApplication's sharedApplication()'s stopModal()
end stopManagerModal

on showAllowlistValidationError(lineNumber, lineOffset, lineLength, lineText)
	set invalidRange to current application's NSMakeRange(lineOffset, lineLength)
	allowlistView's setSelectedRange:invalidRange
	allowlistView's scrollRangeToVisible:invalidRange
	managerWindow's makeFirstResponder:allowlistView
	set validationAlert to current application's NSAlert's alloc()'s init()
	validationAlert's setAlertStyle:(current application's NSAlertStyleWarning)
	validationAlert's setMessageText:("白名单第 " & lineNumber & " 行格式错误")
	validationAlert's setInformativeText:("“" & lineText & "” 不是有效的 IPv4 或 IPv4/CIDR。
例如：8.8.8.8 或 192.168.1.0/24")
	validationAlert's addButtonWithTitle:"返回修改"
	validationAlert's runModal()
end showAllowlistValidationError

on validateAllowlist()
	if allowlistView is "" then return true
	set sourceText to allowlistView's |string|()
	set addressLines to sourceText's componentsSeparatedByString:linefeed
	set whitespaceSet to current application's NSCharacterSet's whitespaceCharacterSet()
	set octetPattern to "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
	set addressPattern to "^(?:" & octetPattern & "\\.){3}" & octetPattern & "(?:/(?:3[0-2]|[12]?[0-9]))?$"
	set addressPredicate to current application's NSPredicate's predicateWithFormat:"SELF MATCHES %@" argumentArray:{addressPattern}
	set currentOffset to 0
	set lineCount to (addressLines's |count|()) as integer
	repeat with lineIndex from 0 to (lineCount - 1)
		set rawLine to (addressLines's objectAtIndex:lineIndex)
		set rawLength to (rawLine's |length|()) as integer
		set trimmedLine to (rawLine's stringByTrimmingCharactersInSet:whitespaceSet)
		set trimmedLength to (trimmedLine's |length|()) as integer
		if trimmedLength > 0 and not (trimmedLine's hasPrefix:"#") then
			set validAddress to (addressPredicate's evaluateWithObject:trimmedLine) as boolean
			if not validAddress then
				my showAllowlistValidationError(lineIndex + 1, currentOffset, rawLength, trimmedLine as text)
				return false
			end if
		end if
		set currentOffset to currentOffset + rawLength + 1
	end repeat
	return true
end validateAllowlist

on windowSave:sender
	if not my validateAllowlist() then return
	if editorHostMode then
		my stopManagerModal(1000)
		return
	end if
	try
		if my isInstalled() then
			set shouldApplyChanges to my isProtected()
			my saveAllowlist(shouldApplyChanges)
		else
			my installAndEnable()
		end if
		set savedListText to my readAllowlist()
		my showManagerWindow(savedListText)
	on error errorText number errorNumber
		if errorNumber is not -128 then my showError("操作失败", errorText, errorNumber)
	end try
end windowSave:

on windowUninstall:sender
	if editorHostMode then
		my stopManagerModal(1001)
		return
	end if
	if not my confirmUninstall() then return
	try
		my uninstallFirewall()
		my showManagerWindow("")
	on error errorText number errorNumber
		if errorNumber is not -128 then my showError("操作失败", errorText, errorNumber)
	end try
end windowUninstall:

on windowToggle:sender
	if editorHostMode then
		my stopManagerModal(1002)
		return
	end if
	try
		set listText to (allowlistView's |string|()) as text
		if my isProtected() then
			my disableProtection()
		else
			my enableProtection()
		end if
		my showManagerWindow(listText)
	on error errorText number errorNumber
		if errorNumber is not -128 then my showError("操作失败", errorText, errorNumber)
	end try
end windowToggle:

on windowClose:sender
	if editorHostMode then
		try
			managerWindow's orderOut:me
		end try
		my stopManagerModal(1003)
	else
		current application's NSApplication's sharedApplication()'s terminate:me
	end if
end windowClose:

on windowQuit:sender
	if editorHostMode then
		try
			managerWindow's orderOut:me
		end try
		my stopManagerModal(1003)
	else
		current application's NSApplication's sharedApplication()'s terminate:me
	end if
end windowQuit:

on pfAddResponderMenuItem(parentMenu, itemTitle, actionName, keyText)
	-- target 保持 nil，让 AppKit 沿 responder chain 把动作交给当前 NSTextView。
	set responderMenuItem to current application's NSMenuItem's alloc()'s initWithTitle:itemTitle action:actionName keyEquivalent:keyText
	responderMenuItem's setKeyEquivalentModifierMask:1048576
	responderMenuItem's setEnabled:true
	parentMenu's addItem:responderMenuItem
end pfAddResponderMenuItem

on configureMainMenu()
	set |pfApplication| to current application's NSApplication's sharedApplication()
	set mainMenu to current application's NSMenu's alloc()'s initWithTitle:""
	mainMenu's setAutoenablesItems:false
	set appMenuItem to current application's NSMenuItem's alloc()'s init()
	appMenuItem's setEnabled:true
	set appMenu to current application's NSMenu's alloc()'s initWithTitle:appTitle
	set quitMenuItem to current application's NSMenuItem's alloc()'s init()
	quitMenuItem's setTitle:("退出 " & appTitle)
	quitMenuItem's setTarget:|pfApplication|
	quitMenuItem's setAction:"terminate:"
	quitMenuItem's setKeyEquivalent:"q"
	quitMenuItem's setKeyEquivalentModifierMask:1048576
	quitMenuItem's setEnabled:true
	appMenu's setAutoenablesItems:false
	appMenu's addItem:quitMenuItem
	appMenuItem's setSubmenu:appMenu
	mainMenu's addItem:appMenuItem
	-- NSTextView 的撤销、剪切、复制、粘贴、全选快捷键依赖标准“编辑”菜单
	-- 和 responder chain；只创建窗口菜单会导致 ⌘A/⌘C/⌘V 全部失效。
	set editMenuItem to current application's NSMenuItem's alloc()'s init()
	editMenuItem's setEnabled:true
	set editMenu to current application's NSMenu's alloc()'s initWithTitle:"编辑"
	editMenu's setAutoenablesItems:true
	my pfAddResponderMenuItem(editMenu, "撤销", "undo:", "z")
	my pfAddResponderMenuItem(editMenu, "剪切", "cut:", "x")
	my pfAddResponderMenuItem(editMenu, "复制", "copy:", "c")
	my pfAddResponderMenuItem(editMenu, "粘贴", "paste:", "v")
	my pfAddResponderMenuItem(editMenu, "全选", "selectAll:", "a")
	editMenuItem's setSubmenu:editMenu
	mainMenu's addItem:editMenuItem
	set windowMenuItem to current application's NSMenuItem's alloc()'s init()
	windowMenuItem's setEnabled:true
	set windowMenu to current application's NSMenu's alloc()'s initWithTitle:"窗口"
	set closeMenuItem to current application's NSMenuItem's alloc()'s init()
	closeMenuItem's setTitle:"关闭窗口"
	closeMenuItem's setTarget:me
	closeMenuItem's setAction:"windowClose:"
	closeMenuItem's setKeyEquivalent:"w"
	closeMenuItem's setKeyEquivalentModifierMask:1048576
	closeMenuItem's setEnabled:true
	windowMenu's setAutoenablesItems:false
	windowMenu's addItem:closeMenuItem
	windowMenuItem's setSubmenu:windowMenu
	mainMenu's addItem:windowMenuItem
	|pfApplication|'s setMainMenu:mainMenu
	|pfApplication|'s setWindowsMenu:windowMenu
	quitMenuItem's setEnabled:true
	closeMenuItem's setEnabled:true
end configureMainMenu

on confirmUninstall()
	set confirmAlert to current application's NSAlert's alloc()'s init()
	confirmAlert's setAlertStyle:(current application's NSAlertStyleWarning)
	confirmAlert's setMessageText:"确定卸载？"
	confirmAlert's setInformativeText:"这会关闭 PF、移除开机自启并删除全部相关文件。"
	confirmAlert's addButtonWithTitle:"卸载"
	confirmAlert's addButtonWithTitle:"取消"
	return ((confirmAlert's runModal()) as integer) is 1000
end confirmUninstall

on showError(errorTitle, errorText, errorNumber)
	set errorAlert to current application's NSAlert's alloc()'s init()
	errorAlert's setAlertStyle:(current application's NSAlertStyleCritical)
	errorAlert's setMessageText:errorTitle
	errorAlert's setInformativeText:(errorText & "（错误号：" & errorNumber & "）")
	errorAlert's addButtonWithTitle:"确定"
	errorAlert's runModal()
end showError

-- 自定义 handler 名加 pf 前缀，避免 add/action/button 被 Cocoa 词典当作命令术语。
on pfCreateButton(parentView, buttonFrame, buttonTitle, actionName)
	set newButton to current application's NSButton's alloc()'s initWithFrame:buttonFrame
	newButton's setTitle:buttonTitle
	newButton's setTarget:me
	newButton's setAction:actionName
	parentView's addSubview:newButton
end pfCreateButton

on showManagerWindow(listText)
	-- 保留上一窗口直到操作完成；重绘新窗口前才替换，避免保存时界面突然隐藏。
	try
		managerWindow's orderOut:me
	end try
	set installedNow to my isInstalled()
	set |protectionIsActive| to my isProtected()
	set windowWidth to 560
	set windowHeight to 410
	if not installedNow then set windowHeight to 180
	set windowFrame to current application's NSMakeRect(0, 0, windowWidth, windowHeight)
	-- NSWindowStyleMaskTitled | Closable | Miniaturizable = 1 | 2 | 4
	-- 不包含 Resizable，因此没有调整大小和最大化功能。
	set windowStyle to 7
	set managerWindow to current application's NSWindow's alloc()'s initWithContentRect:windowFrame styleMask:windowStyle backing:(current application's NSBackingStoreBuffered) defer:false
	managerWindow's setTitle:appTitle
	managerWindow's setMinSize:(current application's NSMakeSize(460, 180))
	managerWindow's setReleasedWhenClosed:false
	set |pfContentView| to managerWindow's contentView()
	set statusField to current application's NSTextField's alloc()'s initWithFrame:(current application's NSMakeRect(20, windowHeight - 62, windowWidth - 40, 42))
	statusField's setEditable:false
	statusField's setBordered:false
	statusField's setDrawsBackground:false
	statusField's setFont:(current application's NSFont's systemFontOfSize:14)
	if installedNow then
		if |protectionIsActive| then
			set statusText to "状态：已安装，防护已开启"
		else
			set statusText to "状态：已安装，防护已关闭"
		end if
		statusField's setStringValue:(statusText & linefeed & "允许直连的目的 IP / CIDR（每行一个）")
	else
		statusField's setStringValue:"状态：尚未安装"
	end if
	|pfContentView|'s addSubview:statusField
	if installedNow then
		set editorFrame to current application's NSMakeRect(20, 72, windowWidth - 40, windowHeight - 145)
		set scrollView to current application's NSScrollView's alloc()'s initWithFrame:editorFrame
		scrollView's setBorderType:(current application's NSBezelBorder)
		scrollView's setHasVerticalScroller:true
		scrollView's setAutohidesScrollers:true
		set allowlistView to current application's NSTextView's alloc()'s initWithFrame:(current application's NSMakeRect(0, 0, windowWidth - 40, windowHeight - 145))
		allowlistView's setFont:(current application's NSFont's monospacedSystemFontOfSize:14 weight:(current application's NSFontWeightRegular))
		allowlistView's setAutomaticQuoteSubstitutionEnabled:false
		allowlistView's setAutomaticDashSubstitutionEnabled:false
		allowlistView's setHorizontallyResizable:false
		allowlistView's setVerticallyResizable:true
		set textContainerObject to allowlistView's textContainer()
		textContainerObject's setContainerSize:(current application's NSMakeSize(windowWidth - 40, 10000000))
		textContainerObject's setWidthTracksTextView:true
		allowlistView's setString:listText
		scrollView's setDocumentView:allowlistView
		|pfContentView|'s addSubview:scrollView
		-- 集中创建 target/action 按钮，避免各按钮的选择器配置不一致。
		set |pfButtonFrame| to current application's NSMakeRect(20, 20, 110, 30)
		my pfCreateButton(|pfContentView|, |pfButtonFrame|, "保存并生效", "windowSave:")
		set |pfButtonFrame| to current application's NSMakeRect(140, 20, 80, 30)
		my pfCreateButton(|pfContentView|, |pfButtonFrame|, "卸载", "windowUninstall:")
		set |pfButtonFrame| to current application's NSMakeRect(windowWidth - 230, 20, 110, 30)
		if |protectionIsActive| then
			my pfCreateButton(|pfContentView|, |pfButtonFrame|, "关闭防护", "windowToggle:")
		else
			my pfCreateButton(|pfContentView|, |pfButtonFrame|, "启用防护", "windowToggle:")
		end if
	else
		set allowlistView to ""
		set |pfButtonFrame| to current application's NSMakeRect(20, 20, 110, 30)
		my pfCreateButton(|pfContentView|, |pfButtonFrame|, "安装并启用", "windowSave:")
	end if
	set closeButton to managerWindow's standardWindowButton:(current application's NSWindowCloseButton)
	closeButton's setTarget:me
	closeButton's setAction:"windowClose:"
	set |pfApplication| to current application's NSApplication's sharedApplication()
	-- 成品 App 不能使用 runModalForWindow：模态会话会禁用应用菜单。
	-- 但脚本编辑器不是 stay-open App，测试时必须用模态循环保持脚本执行状态；
	-- 同时不能替换脚本编辑器自己的主菜单，也不能 terminate 脚本编辑器进程。
	if not editorHostMode then
		my configureMainMenu()
		|pfApplication|'s setActivationPolicy:0
	end if
	|pfApplication|'s activateIgnoringOtherApps:true
	-- NSMakeRect(0, 0, ...) 的原点是屏幕左下角；显示前必须显式居中。
	-- center 也可能与 AppleScript/Cocoa 术语冲突，使用竖线强制按选择器解析。
	managerWindow's |center|()
	managerWindow's makeKeyAndOrderFront:me
	if editorHostMode then
		set managerResponse to 0
		|pfApplication|'s runModalForWindow:managerWindow
		return managerResponse
	end if
	return true
end showManagerWindow


on runManagerCore()
	set editorHostMode to my isScriptEditorHost()
	-- AppleScriptObjC 解析器不稳定地把嵌套的 “my handler(my otherHandler())”
	-- 识别成 Cocoa 命令；先存入局部变量可避免 Expected expression 编译错误。
	set initialListText to my readAllowlist()
	if not editorHostMode then
		my showManagerWindow(initialListText)
		return
	end if
	
	-- 脚本编辑器测试模式：模态窗口结束后在这里执行操作并重建窗口，
	-- 因此“运行”按钮会一直保持执行状态，关闭窗口后才回到编辑器。
	set listText to initialListText
	repeat
		set installedBeforeDialog to my isInstalled()
		set responseCode to my showManagerWindow(listText)
		if responseCode is 0 or responseCode is 1003 then exit repeat
		if installedBeforeDialog and allowlistView is not "" then set listText to (allowlistView's |string|()) as text
		try
			if not installedBeforeDialog then
				if responseCode is 1000 then
					my installAndEnable()
					set listText to my readAllowlist()
				end if
			else if responseCode is 1000 then
				set shouldApplyChanges to my isProtected()
				my saveAllowlist(shouldApplyChanges)
			else if responseCode is 1001 then
				if my confirmUninstall() then
					my uninstallFirewall()
					set listText to ""
				end if
			else if responseCode is 1002 then
				if my isProtected() then
					my disableProtection()
				else
					my enableProtection()
				end if
			end if
		on error errorText number errorNumber
			if errorNumber is not -128 then my showError("操作失败", errorText, errorNumber)
		end try
	end repeat
	-- 不要在 AppleScript Applet 内调用 NSApplication.run()：它会让 Applet
	-- 一直处于“脚本正在执行”，菜单 terminate: 会被延后而无法真正退出。
	-- 成品必须用 osacompile -s 构建为 stay-open App，由 Applet 管理事件循环。
end runManagerCore

on runManager()
	try
		my runManagerCore()
	on error errorText number errorNumber
		if errorNumber is not -128 then my showError("程序无法启动", errorText, errorNumber)
	end try
end runManager

-- 只负责切换到主线程；stay-open Applet 在本 handler 返回后继续处理 AppKit 事件。
my performSelectorOnMainThread:"runManager" withObject:(missing value) waitUntilDone:true
