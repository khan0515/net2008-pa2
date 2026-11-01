# Name: Zarak Khan
# Student ID: 041075276
# NET2008 - Fleet Compliance Auditor

import json
import sys
import xml.etree.ElementTree as ET
import yaml

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


def load_inventory(file_name):
    """Read the XML inventory"""
    tree = ET.parse(file_name)
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
    with open(file_name, "r") as file:
        policy = yaml.safe_load(file)

    if policy is None:
        policy = {}

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
    """Run the audit and write audit.json."""
    inventory_file = sys.argv[1]
    policy_file = sys.argv[2]

    site, devices, skipped = load_inventory(inventory_file)

    policy = load_policy(policy_file)

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


if __name__ == "__main__":
    main()
