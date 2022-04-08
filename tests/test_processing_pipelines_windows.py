from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.pipelines.windows import windows_pipeline
import pytest

@pytest.fixture
def application_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Application service Test
        status: test
        logsource:
            service: application
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
            condition: sel
    """)

@pytest.fixture
def security_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Security service Test
        status: test
        logsource:
            service: security
            product: windows
        detection:
            sel:
                EventID: 4661
                ObjectName: test
            condition: sel
    """)
    
@pytest.fixture
def firewall_as_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Security service Test
        status: test
        logsource:
            service: firewall-as
            product: windows
        detection:
            sel:
                Action: block
            condition: sel
    """)
    
@pytest.fixture
def ps_script_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Powershell Script category Test
        status: test
        logsource:
            category: ps_script
            product: windows
        detection:
            sel:
                ScriptBlockText: test
            condition: sel
    """)

def test_windows_application(application_sigma_rule):
    backend = TextQueryTestBackend(windows_pipeline())
    assert backend.convert(application_sigma_rule) == ['Channel="Application" and CommandLine="test.exe foo bar"']

def test_windows_security(security_sigma_rule):
    backend = TextQueryTestBackend(windows_pipeline())
    assert backend.convert(security_sigma_rule) == ['Channel="Security" and EventID=4661 and ObjectName="test"']

def test_windows_firewall_as(firewall_as_sigma_rule):
    backend = TextQueryTestBackend(windows_pipeline())
    assert backend.convert(firewall_as_sigma_rule) == ['Channel="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and Action="block"']
  
def test_windows_ps_script(ps_script_sigma_rule):
    backend = TextQueryTestBackend(windows_pipeline())
    assert backend.convert(ps_script_sigma_rule) == ['Channel="Microsoft-Windows-PowerShell/Operational" and EventID=4104 and ScriptBlockText="test"']  

