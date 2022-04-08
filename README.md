![Tests](https://github.com/SigmaHQ/pySigma-pipeline-sysmon/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/9c695cb26aae10cb8107941388340ec1/raw)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma windows Processing Pipeline

This is the windows service processing pipeline for pySigma. It provides the package `sigma.pipeline.windows` with the `windows_pipeline` function that returns a ProcessingPipeline object.

Currently the pipeline adds support for the following event types (Sigma logsource service and category to Channel mapping):

* builtin service
    * application
    * security
    * system
    * sysmon
    * powershell
    * powershell-classic
    * dns-server
    * driver-framework
    * dhcp
    * ntlm
    * windefend
    * printservice-admin
    * printservice-operational
    * smbclient-security
    * applocker
    * msexchange-management
    * microsoft-servicebus-client
    * ldap_debug
    * taskscheduler
    * wmi
    * codeintegrity-operational
    * firewall-as
    * bits-client
* builtin category
    * ps_module
    * ps_script
    * ps_classic_start
    * ps_classic_provider_start
    * ps_classic_script

This pipelines is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)
* [frack113](https://github.com/frack113)
