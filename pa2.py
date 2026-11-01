# Name: Zarak Khan
# Student ID: 041075276
# NET2008 - Fleet Compliance Auditor

import json
import sys
import xml.etree.ElementTree as ET
import yaml


class AuditError(Exception):
    """Raised when an input file is missing."""


class Device:
    """One network device from the inventory file."""

    def __init__(self, device_id, role, os_version, owner):
        """Store the basic information about a device."""
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interface_statuses = []

    def add_interface(self, status):
        """Remember the status of one interface."""
        self.interface_statuses.append(status)

    def count_down_interfaces(self):
        """Return how many interfaces are down."""
        count = 0
        for status in self.interface_statuses:
            if status == "down":
                count = count + 1
        return count

    def has_owner(self):
        """Return True if the device has an owner."""
        if self.owner is None:
            return False
        if self.owner.strip() == "":
            return False
        return True


def version_to_list(version):
    """Turn a version into a list of numbers."""
    numbers = []
    for part in str(version).split("."):
        numbers.append(int(part))
    return numbers


def is_older_version(found, required):
    """Return True if the found version is older."""
    found_numbers = version_to_list(found)
    required_numbers = version_to_list(required)

    while len(found_numbers) < len(required_numbers):
        found_numbers.append(0)
    while len(required_numbers) < len(found_numbers):
        required_numbers.append(0)

    for i in range(len(found_numbers)):
        if found_numbers[i] < required_numbers[i]:
            return True
        if found_numbers[i] > required_numbers[i]:
            return False

    return False


def load_inventory(file_name):
    """Read the XML inventory"""
    try:
        tree = ET.parse(file_name)
    except FileNotFoundError:
        raise AuditError("Error: file not found: " + file_name)
    except ET.ParseError:
        raise AuditError("Error: file is not valid XML: " + file_name)
    root = tree.getroot()

    site = root.get("site")
    devices = []
    skipped = 0

    for device_element in root.findall("device"):
        device_id = device_element.get("id")
        if device_id is None:
            skipped = skipped + 1
            continue

        role = device_element.get("role")
        os_version = device_element.get("os")

        owner_element = device_element.find("owner")
        if owner_element is None:
            owner = None
        else:
            owner = owner_element.text

        device = Device(device_id, role, os_version, owner)

        for interface_element in device_element.findall("interface"):
            device.add_interface(interface_element.get("status"))

        devices.append(device)

    return site, devices, skipped


def load_policy(file_name):
    """Read the YAML policy."""
    try:
        with open(file_name, "r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)
    except FileNotFoundError:
        raise AuditError("Error: policy not found: " + file_name)
    except yaml.YAMLError:
        raise AuditError("Error: policy is not valid YAML: " + file_name)

    if policy is None:
        policy = {}

    if not isinstance(policy, dict):
        raise AuditError("Error: policy file is not a mapping: " + file_name)

    return policy


def check_device(device, policy):
    """Return a list of violations"""
    violations = []

    if "min_os" in policy:
        min_os = policy["min_os"]
        if min_os is None:
            min_os = {}

        if device.role not in min_os:
            violations.append({
                "device": device.device_id,
                "type": "unknown_role",
                "role": device.role,
            })

        elif device.os_version is not None:
            required = str(min_os[device.role])
            if is_older_version(device.os_version, required):
                violations.append({
                    "device": device.device_id,
                    "type": "os_outdated",
                    "found": device.os_version,
                    "required": required,
                })

    if policy.get("require_owner") == True:
        if not device.has_owner():
            violations.append({
                "device": device.device_id,
                "type": "missing_owner",
            })

    if "max_down_interfaces" in policy:
        down = device.count_down_interfaces()
        if down > policy["max_down_interfaces"]:
            violations.append({"device": device.device_id, "type": "too_many_down", "down": down,})

    return violations


def count_roles(devices):
    """Return a dictionary of role"""
    roles = {}
    for device in devices:
        if device.role in roles:
            roles[device.role] = roles[device.role] + 1
        else:
            roles[device.role] = 1
    return roles


def count_interfaces(devices):
    """Return how many interfaces are up/down"""
    counts = {"up": 0, "down": 0, "other": 0}
    for device in devices:
        for status in device.interface_statuses:
            if status == "up":
                counts["up"] = counts["up"] + 1
            elif status == "down":
                counts["down"] = counts["down"] + 1
            else:
                counts["other"] = counts["other"] + 1
    return counts


def find_compliant(devices, violations):
    """Return a list of ids for devices that have no violations."""
    bad_ids = []
    for violation in violations:
        bad_ids.append(violation["device"])

    compliant = []
    for device in devices:
        if device.device_id not in bad_ids:
            compliant.append(device.device_id)

    compliant.sort()
    return compliant


def write_report(report):
    """Write the report dictionary to audit.json."""
    with open("audit.json", "w") as file:
        json.dump(report, file, indent=2)


def main():
    """Check the arguments, run the audit, and return an exit code."""
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2

    inventory_file = sys.argv[1]
    policy_file = sys.argv[2]

    try:
        site, devices, skipped = load_inventory(inventory_file)
        policy = load_policy(policy_file)
    except AuditError as error:
        print(error)
        return 1

    violations = []
    for device in devices:
        device_violations = check_device(device, policy)
        for violation in device_violations:
            violations.append(violation)

    report = {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": count_roles(devices),
        "interfaces": count_interfaces(devices),
        "violations": violations,
        "compliant": find_compliant(devices, violations),
    }

    write_report(report)
    print("Audited", len(devices), "devices,", len(violations), "violations found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())