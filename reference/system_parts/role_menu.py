# Menu-driven, role-based access control (RBAC).
#
# run_menu() does the looping and the "Back" option for you, which removes the
# usual bugs (comparing the choice to an int, forgetting Back, infinite loops).
# Each option is (label, function); a function takes no arguments, so pass
# extra values in with lambda or by defining the function inside the caller.
#
# Enforce access control by STRUCTURE: a role's menu simply never contains a
# "decrypt" option, and the private key is never handed to that role's code.


def run_menu(title, options, back_label="Back"):
    while True:
        print(f"\n--- {title} ---")
        for number, (label, _) in enumerate(options, start=1):
            print(f"{number}. {label}")
        print(f"{len(options) + 1}. {back_label}")

        choice = input("Choice: ").strip()

        if choice == str(len(options) + 1):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            options[int(choice) - 1][1]()
        else:
            print("Invalid choice.")


# ---------- optional: an explicit permission table ----------

ROLE_PERMISSIONS = {
    "doctor": {"add", "view", "decrypt", "verify"},
    "nurse": {"view", "verify"},
    "admin": {"view_summary", "verify"},
}


def can(role, action):
    return action in ROLE_PERMISSIONS.get(role, set())


def require(role, action):
    """Raises PermissionError unless the role may do the action."""
    if not can(role, action):
        raise PermissionError(f"{role} is not allowed to {action}")


if __name__ == "__main__":
    def doctor_menu():
        run_menu("Doctor Menu", [
            ("Add a record", lambda: print("(adding a record)")),
            ("Decrypt a record", lambda: print("(decrypting)")),
        ])

    def nurse_menu():
        run_menu("Nurse Menu", [
            ("View records", lambda: print("(listing records)")),
            ("Verify a record", lambda: print("(verifying)")),
        ])

    print("nurse can decrypt?", can("nurse", "decrypt"))
    try:
        require("nurse", "decrypt")
    except PermissionError as error:
        print("blocked:", error)

    run_menu("HealthSecure", [("Doctor", doctor_menu), ("Nurse", nurse_menu)],
             back_label="Exit")
