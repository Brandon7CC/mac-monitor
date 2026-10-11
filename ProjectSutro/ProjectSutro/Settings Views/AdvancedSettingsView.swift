//
//  AdvancedSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework
import OSLog


struct SystemDetailsView: View {
    var macOSVersion: String {
        ProcessInfo.processInfo.operatingSystemVersionString
    }
    
    var cpuNameBrand: String {
        var socName: [Int8] = Array(repeating: 0, count: 128)
        var socNameSize = socName.count
        sysctlbyname("machdep.cpu.brand_string", &socName, &socNameSize, nil, 0)
        return String(cString: socName)
    }
    
    var memorySize: Int {
        var size: UInt64 = 0
        var len = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &size, &len, nil, 0)
        return Int(Double(size) / (1024 * 1024 * 1024))
    }
    
    var sipStatus: String {
        var status: Int32 = 0
        var size = MemoryLayout.size(ofValue: status)
        sysctlbyname("security.mac.amfi.launch_constraints_enforced", &status, &size, nil, 0)
        if status == 1 {
            return "Enabled"
        }
        return "Disabled"
    }
    
    var csrConfig: [String] {
        var ret_config: [String] = []
        let csr_mask_strings = [
            "CSR_ALLOW_UNTRUSTED_KEXTS",
            "CSR_ALLOW_UNRESTRICTED_FS",
            "CSR_ALLOW_TASK_FOR_PID",
            "CSR_ALLOW_KERNEL_DEBUGGER",
            "CSR_ALLOW_APPLE_INTERNAL",
            "CSR_ALLOW_DESTRUCTIVE_DTRACE",
            "CSR_ALLOW_UNRESTRICTED_DTRACE",
            "CSR_ALLOW_UNRESTRICTED_NVRAM",
            "CSR_ALLOW_DEVICE_CONFIGURATION",
            "CSR_ALLOW_ANY_RECOVERY_OS",
            "CSR_ALLOW_UNAPPROVED_KEXTS",
            "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE",
            "CSR_ALLOW_UNAUTHENTICATED_ROOT"
        ]
        
        var mask_index: Int = 0
        for mask in csr_mask_strings {
            if (csr_check(1 << mask_index) == 0) {
                ret_config.append(mask)
            }
            mask_index += 1
        }
        return ret_config
    }
    
    var body: some View {
        Text("**System details**").font(.title2)
        GroupBox {
            VStack(alignment: .leading) {
                Text("Hardware and software:").font(.headline)
                HStack {
                    Text("**macOS:**").font(.title3)
                    GroupBox {
                        Text("`\(macOSVersion)`").frame(alignment: .leading)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    Text("**Processor / SoC:**").font(.title3)
                    GroupBox {
                        Text("`\(cpuNameBrand)`").frame(alignment: .leading)
                    }
                    Text("**Memory:**").font(.title3)
                    GroupBox {
                        Text("`\(memorySize) GB`").frame(alignment: .leading)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                Divider()
                
                Text("Security controls:").font(.headline)
                
//                HStack {
//                    Text("**Gatekeeper assessments:**").font(.title3)
//                    GroupBox {
//                        HStack {
//                            if gatekeeperStatus == "Disabled" {
//                                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
//                            }
//                            Text("`\(gatekeeperStatus)`").frame(alignment: .leading)
//                        }
//
//                    }
//                }.frame(maxWidth: .infinity, alignment: .leading)
                
                HStack {
                    Text("**System Integrity Protection (SIP):**").font(.title3)
                    HStack {
                        GroupBox {
                            HStack {
                                if sipStatus == "Disabled" {
                                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                                }
                                Text("`\(sipStatus)`").frame(alignment: .leading)
                            }
                            
                            
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                
                ScrollView(.horizontal) {
                    HStack {
                        ForEach(csrConfig, id: \.self) { elem in
                            
                            GroupBox {
                                Text("`\(elem)`")
                            }
                            
                        }
                    }
                    
                }
            }.frame(maxWidth: .infinity)
        }
    }
}


struct AdvancedView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading) {
                Text("**Sensor details**").font(.title2)
                GroupBox {
                    VStack(alignment: .leading) {
                        Label("**Sensor ID**", systemImage: "touchid").font(.title3).frame(maxWidth: .infinity, alignment: .leading)
                        HStack {
                            GroupBox {
                                Text("`\(systemExtensionManager.sensorID)`").frame(alignment: .leading)
                            }
                        }
                    }.frame(maxWidth: .infinity)
                }
                
                Divider().padding(.bottom)
                
                SystemDetailsView()
                
                Divider().padding(.bottom)

                
                Text("**Manage Security Extension**").font(.title2)
                GroupBox {
                    VStack(alignment: .leading) {
                        Text("**Warning**: Uninstalling the security extension will disable the ability of the Mac Monitor Security Extension to collect Endpoint Security events from macOS. To enable event tracing the security extension must be installed.").frame(maxWidth: .infinity)
                        Divider()
                        GroupBox {
                            HStack {
                                Group {
                                    Button("Install") {
                                        systemExtensionManager.activateSystemExtension()
                                    }
                                    Button("Uninstall") {
                                        systemExtensionManager.uninstallSystemExtension()
                                    }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8)
                                }
                            }.frame(maxWidth: .infinity, alignment: .center)
                        }
                    }.frame(maxWidth: .infinity)
                }
                
                Divider().padding(.bottom)
                
                Text("**Full Disk Access (FDA)**").font(.title2)
                GroupBox {
                    VStack(alignment: .leading) {
                        Text("**Requirement**: The Mac Monitor security extension requires full disk access to monitor system events. Without the help of MDM (Mobile Device Management) profiles this *must* be enabled by the end user. Use the following button to make sure the Security Extension has full disk access.").frame(maxWidth: .infinity)
                        Divider()
                        GroupBox {
                            HStack {
                                Button("Full Disk Access") {
                                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
                                }
                            }.frame(maxWidth: .infinity, alignment: .center)
                        }
                    }.frame(maxWidth: .infinity)
                }
            }
        }
        
    }
}
