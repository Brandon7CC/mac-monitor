# So you want to build an Endpoint Security app?
> Author: [Brandon Dalton](https://redcanary.com/authors/brandon-dalton/)

## **Overview**
AtomicESClient (a very small Endpoint Security (ES) client). AtomicESClient's goal is to provide an easy to follow example for quickly getting up and going with Apple's Endpoint Security APIs. This code should only be used as if it were written on a chalkboard -- in other words, purely for example. AtomicESClient is the very distilled version of an ES client with one event subscription.

## **Why?**
We have received lots of requests to open source the "Red Canary Mac Monitor"! While this is not something I can do on my own -- we're always an open book when it comes to helping people learn and get familiar with complex security topics like ES. As a result of this feedback:

We're releasing simple Swift program of under 200 lines of code which (for educational use) shows the basics of how to:
* Create an "entry point" and logger callback function
* Model a basic `es_message_t` and process execution event `ES_EVENT_TYPE_NOTIFY_EXEC`.
* A new ES client
  * Handle appropriate errors
* Subscribe to events
* Compile and sign your `Mach-O` to be free of any holes with pre-defined entitlements.

ES is simply a public `C` API with extensive documentation and sample code release not just by Apple, but also by others. For more information on complete implementations please checkout these incredible resources:
 * ES documentation: https://developer.apple.com/documentation/endpointsecurity
 * ES sample code: ["Monitoring System Events with Endpoint Security"](https://developer.apple.com/documentation/endpointsecurity/monitoring_system_events_with_endpoint_security)
 * Filtering Network Traffic [(this sample code will be invaluable for understanding XPC)](https://developer.apple.com/documentation/networkextension/filtering_network_traffic)!
 * ProcessMonitor by Patrick Wardle: https://objective-see.org/blog/blog_0x47.html
 * FileMonitor by Patrick Wardle: https://objective-see.org/blog/blog_0x48.html
 * ESFang by Connor Morley: https://github.com/WithSecureLabs/ESFang
 
 > **The goal of AtomicESClient is simply to provide individuals with a *very* clear place to start -- nothing more or less.**

## **Getting going!**
* Join the Apple Developer Program: cost $99/year (I had to pay too): https://developer.apple.com/programs/enroll/
* Request the Endpoint Security entitlement: https://developer.apple.com/contact/request/system-extension/
* Download the Swift file (purely for educational use)

### Option #1 (without Xcode)
* Download the Swift and entitlements property list files
* Compile the source:
  * You need to link with `libbsm.tbd` for `audit_token_to_pid`
  * and with `libEndpointSecurity.tbd` for ES functionality like `es_new_client` and `es_exec_arg`
  * Something like: 
  
  `swiftc AtomicESClient.swift -L /Applications/Xcode.app/.../MacOSX.sdk/usr/lib/ -lEndpointSecurity -lbsm -o AtomicESClient`
* Sign the Mach-O with your developer certificate and entitlements:

`codesign -s $CERT --entitlements $ENT_PLIST --force --timestamp --options hard,kill,library-validation $ATOMIC_ES_CLIENT`
  * `$CERT` is the environment variable representing your Apple Developer certificate stored in Keychain. For me it's `Developer ID Application: Brandon Dalton (UA6JCQGF3F)`.
  * `$ENT_PLIST` is the environment variable representing the **path** to your entitlements property list file (XML formatted):
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
    <dict>
        <key>com.apple.developer.endpoint-security.client</key>
        <true/>
    </dict>
  </plist>
  ```
  * `$ATOMIC_ES_CLIENT` is the environment variable representing the **path** to your compiled `AtomicESClient` code.

### Option #2 (with Xcode)
* Make a new Xcode "Command Line Tool" project and name it `AtomicESClient`
* Replace the code in `main.swift` with the `AtomicESClient.swift` code
* Add the Endpoint Security Entitlement to your target's `AtomicESClient.entitlements` file.
  * Key by the name of: `com.apple.developer.endpoint-security.client`
* Next, under "Signing & Capabilities" ensure that "Automatically manage signing" is not enabled.
* Give your target an appropriate bundle identifier e.g. for me I'd use something like `com.redcanary.atomicESClient`
* Ensure that your development team is selected along with your signing certificate (e.g. `Developer ID: Application`)
* If App Sandboxing is enabled remove it (can also be done from the `.entitlements` file)
* Under your project's "Build Phases" tab go to the "Link Binaries With Libraries" section:
  * You need to link with `libbsm.tbd` for `audit_token_to_pid`
  * and with `libEndpointSecurity.tbd` for ES functionality like `es_new_client` and `es_exec_arg`
* Ensure that Xcode is able to execute the `AtomicESClient` Mach-O as `root` by going to:
  * "Product" > "Scheme" > "Edit Scheme..."
  * Under "Run" > "Info" > "Debug Process As": `root`

![Signing & Capabilities](https://github.com/redcanaryco/mac-monitor/blob/main/Resources/signing-capabilities.png?raw=true)
![Build Phases](https://github.com/redcanaryco/mac-monitor/blob/main/Resources/build-phases.png?raw=true)
![Run As](https://github.com/redcanaryco/mac-monitor/blob/main/Resources/run-as.png?raw=true)

### **Running**
* Endpoint Security **requires** Full Disk Access. This is a defined requirement in the API. Even if you use Apple's `/usr/bin/eslogger` tool you'll still need to enable Full Disk Access (part of TCC) for the host application. Likely something like `Terminal.app` or `iTerm2.app`.
  * To make this *even more clear* please refer to `es_new_client_result_t` which has the following enumeration:
    * `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`: "This error indicates the app lacks Transparency, Consent, and Control (TCC) approval from the user."
* Similarly, you *need* to run any ES client with elevation -- this makes sense right? See:
  * `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`: "The caller isn’t running as root."
* You also do *NEED* the ES entitlement in a *vast* majority of cases (without lowering macOS' security posture). See:
  * `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`: "The caller isn’t properly entitled to connect to Endpoint Security."
* **Optional**: Disabling System Integrity Protection (SIP) will aid you during the development process: using `lldb` to debug your Security Extension. I did most development with SIP enabled and then used it to debug more difficult to identify problems at the end of development. **PLEASE** do not forget to re-enable SIP on your development machine after you’re done!

### Did you do it right?
> When all is said and done you should see output like the following!
```shell
> sudo ./AtomicESClient
Password:
[ES CLIENT SUCCESS] We successfully created a new Endpoint Security client!
{"initiating_process_signing_id":"com.apple.xpc.launchd","id":"07B2FB1B-39FD-447F-95C3-17A352B8418E","initiating_pid":1,"es_event_type":"ES_EVENT_TYPE_NOTIFY_EXEC","initiating_process_path":"/sbin/launchd","exec_event":{"process_path":"/usr/libexec/xpcproxy","process_name":"xpcproxy","pid":43459,"id":"321EEBC4-6753-45CA-ACFD-B75C633AA873","signing_id":"com.apple.xpc.proxy","is_platform_binary":true,"is_adhoc_signed":false,"command_line":"xpcproxy application.com.apple.iCal.1152921500311882688.1152921500311882957"},"mach_time":655266102521,"initiating_process_name":"launchd"}
```