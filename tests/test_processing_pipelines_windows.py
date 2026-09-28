from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.windows import windows_logsource_pipeline, windows_audit_pipeline
from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation
from sigma.processing.conditions import RuleProcessingItemAppliedCondition
import pytest

@pytest.fixture
def backend_windows_logosurce_pipeline():
    return TextQueryTestBackend(windows_logsource_pipeline())

@pytest.fixture
def backend_windows_logosurce_audit():
    return TextQueryTestBackend(windows_audit_pipeline() + windows_logsource_pipeline())

def test_windows_application(backend_windows_logosurce_pipeline):
    assert backend_windows_logosurce_pipeline.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['Channel="Application" and CommandLine="test.exe foo bar"']

def test_windows_security(backend_windows_logosurce_pipeline):
    assert backend_windows_logosurce_pipeline.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['Channel="Security" and EventID=4661 and ObjectName="test"']

def test_windows_firewall_as(backend_windows_logosurce_pipeline):
    assert backend_windows_logosurce_pipeline.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['Channel="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and Action="block"']

def test_windows_ps_script(backend_windows_logosurce_pipeline):
    assert backend_windows_logosurce_pipeline.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['(Channel in ("Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational")) and EventID=4104 and ScriptBlockText="test"']

def test_windows_audit_process_creation(backend_windows_logosurce_audit):
    assert backend_windows_logosurce_audit.convert(
        SigmaCollection.from_yaml("""
            title: Windows process creation rule test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "cmd.exe"
                    ParentImage: "w3p.exe"
                condition: sel
        """)
    ) == ['Channel="Security" and EventID=4688 and NewProcessName="cmd.exe" and ParentProcessName="w3p.exe"']

def test_windows_audit_registry_event(backend_windows_logosurce_audit):
    assert backend_windows_logosurce_audit.convert(
        SigmaCollection.from_yaml("""
            title: Windows registry event rule test
            status: test
            logsource:
                category: registry_event
                product: windows
            detection:
                sel:
                    ObjectName: test
                condition: sel
        """)
    ) == ['Channel="Security" and EventID=4657 and (OperationType in ("New registry value created", "Existing registry value modified")) and ObjectName="test"']

def test_windows_audit_registry_set_fieldmapping(backend_windows_logosurce_audit):
    assert backend_windows_logosurce_audit.convert(
        SigmaCollection.from_yaml("""
            title: Windows registry set rule test
            status: test
            logsource:
                category: registry_set
                product: windows
            detection:
                sel:
                    Image|endswith: 'powershell.exe'
                    TargetObject|contains: 'CurrentVersion'
                    Details: 'evil.exe'
                condition: sel
        """)
    ) == ['Channel="Security" and EventID=4657 and OperationType="Existing registry value modified" and ProcessName endswith "powershell.exe" and ObjectName contains "CurrentVersion" and NewValue="evil.exe"']

@pytest.mark.parametrize("category", ["registry_event", "registry_add"])
def test_windows_audit_registry_fieldmapping_all_categories(backend_windows_logosurce_audit, category):
    query = backend_windows_logosurce_audit.convert(
        SigmaCollection.from_yaml(f"""
            title: Windows registry rule test
            status: test
            logsource:
                category: {category}
                product: windows
            detection:
                sel:
                    Image: 'regedit.exe'
                    TargetObject|contains: 'Services'
                condition: sel
        """)
    )[0]
    assert ' and ProcessName="regedit.exe"' in query
    assert 'ObjectName contains "Services"' in query
    assert "NewProcessName" not in query and "TargetObject" not in query

def test_windows_audit_registry_mapping_does_not_affect_process_creation(backend_windows_logosurce_audit):
    assert backend_windows_logosurce_audit.convert(
        SigmaCollection.from_yaml("""
            title: Windows process creation rule test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: "cmd.exe"
                condition: sel
        """)
    ) == ['Channel="Security" and EventID=4688 and NewProcessName="cmd.exe"']

def test_windows_audit_registry_eventtype_fails(backend_windows_logosurce_audit):
    with pytest.raises(SigmaTransformationError, match="4657"):
        backend_windows_logosurce_audit.convert(
            SigmaCollection.from_yaml("""
                title: Windows registry add rule test
                status: test
                logsource:
                    category: registry_add
                    product: windows
                detection:
                    sel:
                        EventType: CreateKey
                        TargetObject|contains: 'Run'
                    condition: sel
            """)
        )

def test_windows_logsource_identifiers_unique():
    identifiers = [item.identifier for item in windows_logsource_pipeline().items]
    assert len(identifiers) == len(set(identifiers))
    assert "windows_ps_script_logsource" in identifiers

@pytest.mark.parametrize("category,applied", [("ps_script", True), ("ps_module", False)])
def test_windows_ps_logsource_identifier_per_category(category, applied):
    downstream = ProcessingPipeline(priority=20, items=[
        ProcessingItem(
            identifier="marker",
            transformation=AddConditionTransformation({"Marker": "hit"}),
            rule_conditions=[RuleProcessingItemAppliedCondition("windows_ps_script_logsource")],
        )
    ])
    query = TextQueryTestBackend(windows_logsource_pipeline() + downstream).convert(
        SigmaCollection.from_yaml(f"""
            title: Powershell category Test
            status: test
            logsource:
                category: {category}
                product: windows
            detection:
                sel:
                    ScriptBlockText: test
                condition: sel
        """)
    )[0]
    assert ('Marker="hit"' in query) == applied
