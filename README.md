![Tests](https://github.com/SigmaHQ/pySigma-pipeline-windows/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/143d6c718b5bbc9fb7c0e33ed06b0f85/raw/SigmaHQ-pySigma-pipeline-windows.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Windows Processing Pipeline

This is the windows service processing pipeline for pySigma. It provides the package `sigma.pipelines.windows` with the following functions that return a ProcessingPipeline object:

* `windows_logsource_pipeline` (pipeline name `windows-logsources`): maps Windows log source services and categories to Channel conditions.
* `windows_audit_pipeline` (pipeline name `windows-audit`): maps generic log sources (`process_creation`, `registry_event`, `registry_set`, `registry_add`, `registry_delete`) to Windows Security audit events.

Currently the `windows_logsource_pipeline` adds support for the following event types (Sigma logsource service and category to Channel mapping):

* builtin category
    * ps_module
    * ps_script
    * ps_classic_start
    * ps_classic_provider_start
    * ps_classic_script

This pipelines is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)
* [frack113](https://github.com/frack113)
