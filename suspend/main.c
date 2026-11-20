/*
 * suspend — suspend the machine to RAM (ACPI S3).
 *
 * Asks powerd first (like poweroff/reboot/halt); if powerd is unreachable it
 * falls back to reboot(2) with RB_SUSPEND.  Unlike the other power commands
 * this one returns: the process resumes when the machine wakes.
 */
extern int cact_ub_suspend(char **argv, int argc);

int main(int argc, char *argv[]) {
    return cact_ub_suspend((char **)argv, argc);
}
