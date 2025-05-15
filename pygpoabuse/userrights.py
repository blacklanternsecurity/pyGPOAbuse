import logging
import os

class UserRights:
    def __init__(self, username, sid, rights=None):
        self._username = username
        self._sid = sid
        
        # Default list of available rights based on SharpGPOAbuse
        self.available_rights = [
            "SeTrustedCredManAccessPrivilege",
            "SeNetworkLogonRight",
            "SeTcbPrivilege",
            "SeMachineAccountPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeInteractiveLogonRight",
            "SeRemoteInteractiveLogonRight",
            "SeBackupPrivilege",
            "SeChangeNotifyPrivilege",
            "SeSystemtimePrivilege",
            "SeTimeZonePrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreateTokenPrivilege",
            "SeCreateGlobalPrivilege",
            "SeCreatePermanentPrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeDebugPrivilege",
            "SeDenyNetworkLogonRight",
            "SeDenyBatchLogonRight",
            "SeDenyServiceLogonRight",
            "SeDenyInteractiveLogonRight",
            "SeDenyRemoteInteractiveLogonRight",
            "SeEnableDelegationPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeAuditPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege",
            "SeBatchLogonRight",
            "SeServiceLogonRight",
            "SeSecurityPrivilege",
            "SeRelabelPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeSystemProfilePrivilege",
            "SeUndockPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeSyncAgentPrivilege",
            "SeTakeOwnershipPrivilege"
        ]
        
        if rights is None:
            self._rights = []
        else:
            self._rights = [right.strip() for right in rights.split(",")]
            # Validate the rights
            for right in self._rights:
                if right not in self.available_rights:
                    logging.warning(f"Right '{right}' is not in the list of known rights")
    
    def generate_inf_file_content(self):
        """Generate the content for GptTmpl.inf file"""
        content = """[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision = 1
[Privilege Rights]
"""
        for right in self._rights:
            content += f"{right} = *{self._sid}\n"
        
        return content
    
    def validate_rights(self):
        """Validate if provided rights are in the known list"""
        invalid_rights = []
        for right in self._rights:
            if right not in self.available_rights:
                invalid_rights.append(right)
        
        return len(invalid_rights) == 0, invalid_rights 