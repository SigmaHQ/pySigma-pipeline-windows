from .windows import windows_logsource_pipeline, windows_audit_pipeline

pipelines = {
    "windows-logsources": windows_logsource_pipeline,
    "windows-audit": windows_audit_pipeline,
}