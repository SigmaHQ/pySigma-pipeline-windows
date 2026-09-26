from ast import Dict
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, FieldMappingTransformation, DetectionItemFailureTransformation
from sigma.processing.conditions import LogsourceCondition, RuleProcessingItemAppliedCondition, IncludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import generate_windows_logsource_items, logsource_windows

windows_generic_category_channel_mapping = {    # map generic windows log sources to windows channel
    "ps_module": {"service": "powershell", "EventID": 4103},
    "ps_script": {"service": "powershell", "EventID": 4104},
    "ps_classic_start": {"service": "powershell-classic", "EventID": 400},
    "ps_classic_provider_start": { "service": "powershell-classic", "EventID": 600},
    "ps_classic_script": { "service": "powershell-classic", "EventID": 800},
}

generic_logsource_to_windows_audit_event_mapping : Dict = {        # map generic Sigma log sources to Windows audit log events for the windows_audit_pipeline
    "process_creation": {
        "EventID": 4688,
    },
    "registry_event": {
        "EventID": 4657,
        "OperationType": [
            "New registry value created",
            "Existing registry value modified",
        ],
    },
    "registry_set": {
        "EventID": 4657,
        "OperationType": "Existing registry value modified",
    },
    "registry_add": {
        "EventID": 4657,
        "OperationType": "New registry value created",
    },
}

windows_audit_registry_categories = ("registry_event", "registry_set", "registry_add")

windows_audit_registry_fieldmappings = {     # Sysmon taxonomy -> event 4657 fields
    "Image": "ProcessName",
    "TargetObject": "ObjectName",
}

windows_audit_registry_unsupported_fields = [   # Sysmon taxonomy fields without a 4657 counterpart
    "EventType",    # no counterpart; OperationType is already set from the log source category
    "NewName",      # key/value renames are not logged by 4657
    "User",         # 4657 splits the account into SubjectUserName/SubjectDomainName
]

def windows_logsource_pipeline() -> ProcessingPipeline:
    the_service=generate_windows_logsource_items(
        cond_field_template="Channel",
        cond_value_template="{source}",
    )

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
        name="Add Channel condition for Windows log sources",
        priority=10,
        items=the_category + the_service
    )

def windows_audit_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Map generic log sources to Windows audit logs",
        priority=10,
        items=[
            processing_item
            for logsource, conditions in generic_logsource_to_windows_audit_event_mapping.items()
            for processing_item in (
                ProcessingItem(
                    identifier=f"windows_{logsource}_condition",
                    transformation=AddConditionTransformation(conditions),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logsource,
                            product="windows",
                        )
                    ]
                ),
                ProcessingItem(
                    identifier=f"windows_{logsource}_logsource",
                    transformation=ChangeLogsourceTransformation(
                        product="windows",
                        service="security",
                    ),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logsource,
                            product="windows",
                        )
                    ]
                )
            )
        ] + [
            # Event 4657 (registry value modified) has its own field names: the acting process is
            # ProcessName (not NewProcessName, which only exists in 4688) and the registry key is
            # ObjectName. These items must run before the generic mapping below.
            ProcessingItem(
                identifier="windows_audit_registry_unsupported_fields",
                transformation=DetectionItemFailureTransformation(
                    "windows-audit: fields " + ", ".join(windows_audit_registry_unsupported_fields)
                    + " have no equivalent in Windows Security event 4657"
                ),
                field_name_conditions=[
                    IncludeFieldCondition(fields=windows_audit_registry_unsupported_fields),
                ],
                rule_condition_linking=any,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition(f"windows_{logsource}_logsource")
                    for logsource in windows_audit_registry_categories
                ]
            ),
            ProcessingItem(
                identifier="windows_audit_registry_fieldmappings",
                transformation=FieldMappingTransformation(windows_audit_registry_fieldmappings),
                rule_condition_linking=any,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition(f"windows_{logsource}_logsource")
                    for logsource in windows_audit_registry_categories
                ]
            ),
            ProcessingItem(
                identifier="windows_audit_fieldmappings",
                transformation=FieldMappingTransformation({
                    "Image": "NewProcessName",
                    "ParentImage": "ParentProcessName",
                    "Details": "NewValue",
                    "LogonId": "SubjectLogonId",
                }),
                rule_conditions=[
                    logsource_windows("security"),
                ]
            )
        ]
    )
