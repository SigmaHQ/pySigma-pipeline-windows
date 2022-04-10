from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_generic_service_channel_mapping = {    # map generic windows log sources to windows channel
    "application": "Application",
    "security": "Security",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "dns-server": "DNS Server",
    "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "dhcp": "Microsoft-Windows-DHCP-Server/Operational",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "printservice-admin": "Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "Microsoft-Windows-PrintService/Operational",
    "smbclient-security": "Microsoft-Windows-SmbClient/Security",
    "applocker": ["Microsoft-Windows-AppLocker/MSI and Script",
                  "Microsoft-Windows-AppLocker/EXE and DLL",
                  "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                  "Microsoft-Windows-AppLocker/Packaged app-Execution"],
    "msexchange-management": "MSExchange Management",
    "microsoft-servicebus-client": "Microsoft-ServiceBus-Client",
    "ldap_debug": "Microsoft-Windows-LDAP-Client/Debug",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "WinEventlog:Microsoft-Windows-Bits-Client/Operational",
}

windows_generic_category_channel_mapping = {    # map generic windows log sources to windows channel
    "ps_module": {"service": "powershell", "EventID": 4103},
    "ps_script": {"service": "powershell", "EventID": 4104},
    "ps_classic_start": {"service": "powershell-classic", "EventID": 400},
    "ps_classic_provider_start": { "service": "powershell-classic", "EventID": 600},
    "ps_classic_script": { "service": "powershell-classic", "EventID": 800},
}

def windows_pipeline():
    the_service=[
        processing_item
        for service_name, channel in windows_generic_service_channel_mapping.items()
        for processing_item in (
            ProcessingItem(
                identifier=f"windows_{service_name}_channel",
                transformation=AddConditionTransformation({
                                "Channel": channel,
                                }
                            ),
                rule_conditions=[
                    LogsourceCondition(
                        service=service_name,
                        product="windows"
                    )
                ]
            ),
            ProcessingItem(
                identifier="windows_{service_name}_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="windows",
                    service=service_name,
                ),
                rule_conditions=[
                    LogsourceCondition(
                        service=service_name,
                        product="windows"
                    )
                ]
            )
        )
    ]

    the_category=[
        processing_item
        for category_name, info in windows_generic_category_channel_mapping.items()
        for processing_item in (
            ProcessingItem(
                identifier=f"windows_{category_name}_channel",
                transformation=AddConditionTransformation({
                                "EventID": info["EventID"],
                                }
                            ),
                rule_conditions=[
                    LogsourceCondition(
                        category= category_name,
                        product="windows"
                    )
                ]
            ),
            ProcessingItem(
                identifier="windows_{category_name}_logsource",
                transformation=ChangeLogsourceTransformation(
                    product="windows",
                    service=info["service"],
                    category=category_name
                ),
                rule_conditions=[
                    LogsourceCondition(
                        category=category_name,
                        product="windows"
                    )
                ]
            )
        )
    ]

    return ProcessingPipeline(
        name="Generic Log Sources to Windows Transformation",
        priority=10,
        items=the_category + the_service
    )

