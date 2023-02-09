from ast import Dict
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, FieldMappingTransformation
from sigma.processing.conditions import LogsourceCondition
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
            for logosurce, conditions in generic_logsource_to_windows_audit_event_mapping.items()
            for processing_item in (
                ProcessingItem(
                    identifier=f"windows_{logosurce}_condition",
                    transformation=AddConditionTransformation(conditions),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logosurce,
                            product="windows",
                        )
                    ]
                ),
                ProcessingItem(
                    identifier=f"windows_{logosurce}_logsource",
                    transformation=ChangeLogsourceTransformation(
                        product="windows",
                        service="security",
                    ),
                    rule_conditions=[
                        LogsourceCondition(
                            category=logosurce,
                            product="windows",
                        )
                    ]
                )
            )
        ] + [
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