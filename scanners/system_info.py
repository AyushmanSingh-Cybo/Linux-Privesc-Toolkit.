
import getpass
import grp
import os
import platform
import pwd


def collect_system_info():
    """Collect basic Linux system information without modifying it."""

    uid = os.getuid()
    gid = os.getgid()

    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = getpass.getuser()

    group_ids = sorted(set(os.getgroups()) | {gid})
    groups = []

    for group_id in group_ids:
        try:
            groups.append(grp.getgrgid(group_id).gr_name)
        except KeyError:
            groups.append(str(group_id))

    os_name = "Unknown Linux distribution"

    try:
        os_details = platform.freedesktop_os_release()
        os_name = os_details.get(
            "PRETTY_NAME",
            os_details.get("NAME", os_name)
        )
    except (OSError, AttributeError):
        os_name = platform.system()

    return {
        "username": username,
        "uid": uid,
        "gid": gid,
        "groups": groups,
        "operating_system": os_name,
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "is_root": uid == 0,
    }


def print_system_info(info):
    """Display collected system information."""

    print(f"  Username         : {info['username']}")
    print(f"  UID              : {info['uid']}")
    print(f"  GID              : {info['gid']}")
    print(f"  Groups           : {', '.join(info['groups'])}")
    print(f"  Operating System : {info['operating_system']}")
    print(f"  Kernel Version   : {info['kernel_version']}")
    print(f"  Architecture     : {info['architecture']}")
    print(
        "  Privilege Level  : "
        + ("Root" if info["is_root"] else "Standard User")
    )


if __name__ == "__main__":
    system_info = collect_system_info()
    print("\nSYSTEM INFORMATION")
    print("-" * 50)
    print_system_info(system_info)
