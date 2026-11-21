import AppKit

final class MenuBar: NSObject {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let status = NSMenuItem(title: "未配对", action: nil, keyEquivalent: "")
    private let isSender: Bool
    private let begin: NSMenuItem
    private let forget: NSMenuItem
    private let onBegin: () -> Void
    private let onForget: () -> Void
    private var pinWindow: NSPanel?

    init(sender: Bool, begin: @escaping () -> Void, forget: @escaping () -> Void) {
        self.isSender = sender
        self.onBegin = begin
        self.onForget = forget
        self.begin = NSMenuItem(title: sender ? "开始配对" : "配对", action: #selector(startPairing), keyEquivalent: "")
        self.forget = NSMenuItem(title: "取消配对", action: #selector(forgetPairing), keyEquivalent: "")
        super.init()
        item.button?.image = NSImage(systemSymbolName: sender ? "mic" : "waveform", accessibilityDescription: "MicBridge")
        item.button?.toolTip = sender ? "MicBridge 发送端" : "MicBridge 接收端"
        let menu = NSMenu()
        menu.autoenablesItems = false
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())
        for entry in [self.begin, self.forget] { entry.target = self; menu.addItem(entry) }
        item.menu = menu
        update(paired: false)
    }

    func update(paired: Bool, busy: Bool = false, storageError: Bool = false, connected: Bool = false) {
        status.title = storageError ? "配对记录不可用" : paired ? (connected ? "已连接" : "已配对") : busy ? "配对中" : "未配对"
        begin.isEnabled = !paired && !busy && !storageError
        forget.title = isSender && busy ? "停止配对" : "取消配对"
        forget.isEnabled = paired || storageError || (isSender && busy)
    }

    @objc private func startPairing() { onBegin() }
    @objc private func forgetPairing() { onForget() }
    @objc private func cancelCode() { onForget() }

    func showCode(_ pin: String) {
        closeCode()
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 330, height: 166), styleMask: [.titled], backing: .buffered, defer: false)
        panel.title = "MicBridge 配对"
        panel.isReleasedWhenClosed = false
        let label = NSTextField(labelWithString: pin)
        label.font = .monospacedDigitSystemFont(ofSize: 42, weight: .semibold)
        let hint = NSTextField(labelWithString: "在接收端输入此码。2 分钟内有效，最多 3 次。")
        let cancel = NSButton(title: "停止配对", target: self, action: #selector(cancelCode))
        let stack = NSStackView(views: [label, hint, cancel])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 12
        stack.frame = NSRect(x: 8, y: 14, width: 314, height: 138)
        panel.contentView?.addSubview(stack)
        pinWindow = panel
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    func closeCode() { pinWindow?.close(); pinWindow = nil }

    func requestPIN(names: [String]) -> (Int, String)? {
        guard !names.isEmpty else { alert("找不到发送端", "确认发送端已启动，两台 Mac 在同一局域网。"); return nil }
        let dialog = NSAlert()
        dialog.messageText = "配对 MicBridge"
        dialog.informativeText = "输入发送端显示的 4 位数字。"
        dialog.addButton(withTitle: "配对")
        dialog.addButton(withTitle: "取消")
        let picker = NSPopUpButton(frame: .zero, pullsDown: false)
        picker.addItems(withTitles: names)
        let field = NSSecureTextField(frame: .zero)
        field.placeholderString = "0000"
        let stack = NSStackView(views: [picker, field])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 270, height: 58)
        for view in [picker as NSView, field as NSView] { view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        dialog.accessoryView = stack
        dialog.window.initialFirstResponder = field
        NSApp.activate(ignoringOtherApps: true)
        guard dialog.runModal() == .alertFirstButtonReturn else { return nil }
        return (picker.indexOfSelectedItem, field.stringValue)
    }

    func alert(_ title: String, _ detail: String) {
        let dialog = NSAlert()
        dialog.messageText = title
        dialog.informativeText = detail
        dialog.addButton(withTitle: "好")
        NSApp.activate(ignoringOtherApps: true)
        dialog.runModal()
    }
}
