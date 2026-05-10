# Chromium-DebugElevator <sup><sub><sup>(`Chrome App-Bound Encryption Decryption`)

![Debugger attached to Chromium](./images/image_1.png)
## 🚀 Overview
Chromium’s App-Bound Encryption was designed to raise the bar for stealing browser secrets. But recent research shows that attackers may not need payload injection, privilege escalation, or noisy post-exploitation tricks to get around it. In some cases, a debugger is enough.

### General Overview of the Debug process
![Decrypted browser data output](./images/image_5.jpg)

### [Chromium - app_bound_encryption_provider_win.cc](https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/os_crypt/app_bound_encryption_provider_win.cc?q=OSCrypt.AppBoundProvider.Decrypt.ResultCode&ss=chromium)
![Breakpoint hit inside Chromium process](./images/image_2.png)

### x64dbg - Unique reference to string
![Extracted App-Bound encrypted key](./images/image_3.png)

### x64dbg - MOVing key to RDX arg
![Decrypted browser data output](./images/image_4.png)
