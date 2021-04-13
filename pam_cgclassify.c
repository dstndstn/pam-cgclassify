#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <syslog.h>
#include <glob.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/*
int
pam_sm_authenticate (pam_handle_t *pamh, int flags,
                     int argc, const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                   const char **argv)
{
    return PAM_IGNORE;
}
 */
 
/* --- session management functions --- */

int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
                         ,const char **argv)
{
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
    uid_t uid;
    pid_t pid;
    int ret;
    char *user_name;
    glob_t theglob;
    char pattern[1024];
    struct passwd *pwd;

    ret = pam_get_item(pamh, PAM_USER, (void *) &user_name);
    if (user_name == NULL || ret != PAM_SUCCESS)  {
        pam_syslog(pamh, LOG_ERR, "open_session - error finding username");
        return PAM_SESSION_ERR;
    }
    //printf("User name %s\n", user_name);

    pwd = pam_modutil_getpwnam(pamh, user_name);
    if (!pwd) {
        pam_syslog(pamh, LOG_ERR, "open_session username '%s' does not exist", user_name);
        return PAM_SESSION_ERR;
    }
    uid = pwd->pw_uid;
    //printf("Passwd uid: %i\n", uid);

    pid = getpid();
    //printf("PID %i\n", pid);

    // This is how Slurm (19.05) structures its cgroups.  The job_* directory is where
    // the actual limits are placed, so that's what we need to find.
    sprintf(pattern, "/sys/fs/cgroup/memory/slurm/uid_%i/job_*", uid);
    if (glob(pattern, GLOB_ERR, NULL, &theglob)) {
        printf("Glob for slurm cgroup failed\n");
        return PAM_SESSION_ERR;
    }

    // Arbitrarily take the FIRST Slurm job that matches!
    //printf("Found %i Slurm job cgroups.\n", (int)(theglob.gl_pathc));
    if (theglob.gl_pathc > 0) {
        //printf("Path: %s\n", theglob.gl_pathv[0]);
        char command[1024];
        sprintf(command, "/usr/bin/cgclassify -g memory:%s %i", theglob.gl_pathv[0] + 21, pid);
        //printf("Command: %s\n", command);
        system(command);
    }

    globfree(&theglob);
    
    return PAM_SUCCESS;
}

