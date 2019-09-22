#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <stdbool.h>

#define MAY_DRY_RUN(function, args...) \
        dry_run ? dry_##function(args) : function(args)
#define streq(s1, s2) (strcmp(s1, s2) == 0)
#define ERRVAR_INNER(a,b) a##b
#define ERRVAR(a,b) ERRVAR_INNER(a,b)
#define ERR(EXP) int ERRVAR(err,__LINE__) = EXP; \
                 if(ERRVAR(err,__LINE__) < 0)assert_perror(errno)

bool dry_run = false;
int pipe_fd[2];

typedef struct _bind_mount_pair {
    char* source;
    char* target;
    bool  readonly;
    struct _bind_mount_pair* next;
} bind_mount_pair;

/* Concatenate DIRECTORY, a slash, and FILE.  Return the result, which the
   caller must eventually free.  */
static char *
concat (const char *directory, const char *file)
{
  bool end_with_slash = (directory[strlen(directory) - 1] == '/');
  const char* file_name = file[0] == '/' ? file + 1: file;
  char *result = malloc (strlen (directory) + (end_with_slash ? 1 : 2) + strlen (file_name));
  assert (result != NULL);

  strcpy (result, directory);
  if(!end_with_slash)strcat (result, "/");
  strcat (result, file_name);
  return result;
}

static int
dry_mkdir_p(const char* directory){
    printf("mkdir %s\n", directory);
    return 0;
}

static void
mkdir_p (const char *directory)
{
  if (strcmp (directory, "/") != 0)
    {
      char *parent = dirname (strdupa (directory));
      mkdir_p (parent);
      int err = mkdir (directory, 0700);
      if (err < 0 && errno != EEXIST)
        assert_perror (errno);
    }
}

static void
rm_rf (const char *directory)
{
  DIR *stream = opendir (directory);

  for (struct dirent *entry = readdir (stream);
       entry != NULL;
       entry = readdir (stream))
    {
      if (strcmp (entry->d_name, ".") == 0
	  || strcmp (entry->d_name, "..") == 0)
	continue;

      char *full = concat (directory, entry->d_name);

      int err = unlink (full);
      if (err < 0)
	{
	  if (errno == EISDIR)
	    /* Recurse (we expect a shallow directory structure so there's
	       little risk of stack overflow.)  */
	    rm_rf (full);
	  else
	    assert_perror (errno);
	}

      free (full);
    }

  closedir (stream);

  int err = rmdir (directory);
  if (err < 0 && errno != ENOENT)
    assert_perror (errno);
}

static bool
is_same_or_parent_of_path(char* source, char* target){
    if(strlen(source) > strlen(target)) return false;
    if(strcmp(source, target) == 0) return true;
    return is_same_or_parent_of_path(source, dirname(target));
}

static bool
is_same_or_parent_of(const bind_mount_pair* source, const bind_mount_pair* target){
    char* st = strdupa(source->target);
    char* tt = strdupa(target->target);
    return is_same_or_parent_of_path(st, tt);
}

/* Write the user/group ID map for PID to FILE, mapping ID to itself.  See
   user_namespaces(7).  */
static void
write_id_map (pid_t pid, const char *file, int id)
{
  char id_map_file[100];
  snprintf (id_map_file, sizeof id_map_file, "/proc/%d/%s", pid, file);

  char id_map[100];

  /* Map root and the current user.  */
  int len = snprintf (id_map, sizeof id_map, "%d %d 1\n", id, id);
  int fd = open (id_map_file, O_WRONLY);
  if (fd < 0)
    assert_perror (errno);

  int n = write (fd, id_map, len);
  if (n < 0)
    assert_perror (errno);

  close (fd);
}

/* Disallow setgroups(2) for PID.  */
static void
disallow_setgroups (pid_t pid)
{
  char file[100];

  snprintf (file, sizeof file, "/proc/%d/setgroups", pid);

  int fd = open (file, O_WRONLY);
  if (fd < 0)
    assert_perror (errno);

  int err = write (fd, "deny", 5);
  if (err < 0)
    assert_perror (errno);

  close (fd);
}

static bool
split_pair(char* pair, char** source, char** target){
    char* temp_source = strtok(pair, ",");
    char* temp_target = strtok(NULL, ",");
    char* type   = strtok(NULL, ",");
    bool readonly;
    if(temp_source == NULL || temp_target == NULL){
        fprintf(stderr, "Source and target should be separate by a ','.\n");
        exit(1);
    }
    if(type == NULL || streq(type, "ro")){
        readonly = true; 
    } else if(streq(type, "rw")){
        readonly = false;
    } else {
        fprintf(stderr, "Unknown bind-mount type %s.\n", type);
        exit(1);
    }
    *source = strdup(temp_source);
    *target = strdup(temp_target);
    return readonly;
}

static bind_mount_pair*
bind_pair(const char* source, const char* target, bool readonly){
    char* real_source = realpath(source, NULL);
    if(real_source == NULL){
        if(errno != ENOENT){
            fprintf(stderr, "Error while resolving path %s.\n", source);
            assert_perror(errno);
        }
        return NULL;
    }
    if(target[0] != '/') {
        fprintf(stderr, "Not an absolute path: %s,\n", target);
        exit(1);
    }
    bind_mount_pair* result = malloc(sizeof(bind_mount_pair));
    result->source = real_source;
    result->target = target;
    result->readonly = readonly;
    result->next = NULL;
    return result;
}

static bind_mount_pair*
map_pairs(char* source_target_list, bind_mount_pair* (*fn)(char* source_target_pair), char* opt_name){
    char* end_str;
    char* source_target = strtok_r(source_target_list, ":", &end_str);
    if(source_target == NULL){
	    fprintf (stderr, "Extra arguments needed for \"%s\".\n", opt_name);
        exit(1);
    }

    bind_mount_pair head = { "", "", true, NULL };
    bind_mount_pair* current = &head;
    for(;source_target != NULL; source_target=strtok_r(NULL, ":", &end_str)){
        current->next = fn(source_target);
        while(current->next != NULL){
            current = current->next;
        }
    }

    return head.next;
}

static bind_mount_pair*
bind_opt_internal(char* source_target){
    char *source, *target;
    bool readonly = split_pair(source_target, &source, &target);
    return bind_pair(source, target, readonly);
}
static bind_mount_pair*
bind_opt(char* source_target_list){
    return map_pairs(source_target_list, bind_opt_internal, "--bind");
}

static bind_mount_pair*
bind_top_opt_internal(char* source_target){
    char *source, *target;
    bool readonly = split_pair(source_target, &source, &target);

    DIR *stream = opendir (source);
    if(stream == NULL){
        fprintf(stderr, "Error while opening %s. Please check if it is a valid directory and you have the access permission.\n", source);
        assert_perror(errno);
    }

    bind_mount_pair head = { "", "", true, NULL };
    bind_mount_pair* current = &head;

    for (struct dirent *entry = readdir (stream);
            entry != NULL;
            entry = readdir (stream))
    {
        /* XXX: Some file systems may not report a useful 'd_type'.  Ignore them
           for now.  */
        assert (entry->d_type != DT_UNKNOWN);

        if (strcmp (entry->d_name, ".") == 0
                || strcmp (entry->d_name, "..") == 0)
            continue;

        char *abs_source = concat (source, entry->d_name);
        char *new_entry = concat (target, entry->d_name);
        current->next = bind_pair(abs_source, new_entry, readonly);
        if(current->next != NULL)current = current->next;
    }

    closedir (stream);
    return head.next;
}
static bind_mount_pair*
bind_top_opt(char* source_target_list){
    return map_pairs(source_target_list, bind_top_opt_internal, "--bind-top");
}

static bind_mount_pair*
bind_temp_opt_internal(char* target){
    char *temp = mkdtemp (strdup ("/tmp/run-in-fsns-XXXXXX"));
    return bind_pair(temp, target, false);
}
static bind_mount_pair*
bind_temp_opt(char* target_list){
    return map_pairs(target_list, bind_temp_opt_internal, "--bind-temp");
}

static bind_mount_pair*
exclude_opt_internal(char* source){
    bind_mount_pair* result = malloc(sizeof(bind_mount_pair));
    result->source = source;
    result->target = "";
    result->readonly = true;
    result->next = NULL;
    return result;
}
static bind_mount_pair*
exclude_opt(char* source_list){
    return map_pairs(source_list, exclude_opt_internal, "--exclude-entries");
}

static void 
exclude(bind_mount_pair* head, bind_mount_pair* exclude_head){
    bind_mount_pair* current = head;
    while(current->next != NULL){
        for(bind_mount_pair* exclude_current = exclude_head;
                exclude_current->next != NULL;
                exclude_current = exclude_current->next){
            if(strcmp(current->next->source, exclude_current->next->source) == 0){
                bind_mount_pair* removed = current->next;
                current->next = removed->next;
                free(removed->source);
                free(removed->target);
                free(removed);
                break;
            }
        }
        if(current != NULL) current = current->next;
    }
}

static void
sort_by_hierarchy(bind_mount_pair* head){
    bind_mount_pair* iter = head->next;
    head->next = NULL;

    while(iter != NULL){
        bind_mount_pair* hiter = head;
        bool parent_found = false;

        for(;hiter->next != NULL;hiter = hiter->next){
            bind_mount_pair* current = hiter->next;
            if(is_same_or_parent_of(iter, current)){
                break;
            }
            if(is_same_or_parent_of(current, iter)){
                parent_found = true;
            } else {
                if(parent_found)break;
            }
        }

        bind_mount_pair* temp = iter;
        iter = iter->next;
        temp->next = hiter->next;
        hiter->next = temp;
    }
}

static int
dry_mount(const char* source, const char* target, const char* filesystem, unsigned long flag, const void* data){
    char* mflag = alloca(28 * sizeof(char));
    strcpy(mflag, "MS_BIND | MS_REC");
    if(flag & MS_RDONLY > 0)strcat(mflag, " | MS_RDONLY");
    printf("mount %s -> %s, %s\n", source, target, mflag);
    return 0;
}

static void
dry_touch(const char* target){
    printf("open or create %s\n", target);
}

static void
touch(const char* target){
    MAY_DRY_RUN(mkdir_p, dirname(strdupa(target)));
	int fd = open (target, O_WRONLY | O_CREAT, 0700);
    if(fd < 0){
        assert_perror(errno);
    }
    close(fd);
}

static void
do_mount(char* root, bind_mount_pair* bind_mounts){
    char* real_root = realpath(root, NULL);
    if(real_root == NULL)assert_perror(errno);

    for(bind_mount_pair* iter = bind_mounts;
            iter != NULL;
            iter = iter->next){
        char* target_path = concat(real_root, iter->target);

        struct stat statbuf;
        if(stat(iter->source, &statbuf) != 0)assert_perror(errno);
        if(S_ISDIR(statbuf.st_mode)){
            MAY_DRY_RUN(mkdir_p, target_path);
        } else {
            MAY_DRY_RUN(touch, target_path);
        }
        unsigned long flag = iter->readonly ? MS_BIND | MS_REC | MS_RDONLY : MS_BIND | MS_REC;
        ERR(MAY_DRY_RUN(mount, iter->source, target_path, "none", flag, NULL));
        free(target_path);
    }
}

static int
dry_chdir(const char* dir){
    printf("chdir %s\n", dir);
    return 0;
}

static int
dry_chroot(const char* dir){
    printf("chroot %s\n", dir);
    return 0;
}

static int
dry_execvp(char* command, char *argv[]){
    printf("exec %s", command);
    for(int i = 1; argv[i] != NULL; i++){
        printf(" %s", argv[i]);
    }
    printf("\n");
    return 0;
}

int
main (int argc, char *argv[])
{
    int index;
    bool use_default = true;
    char* working_dir = NULL;

    bind_mount_pair bind_directly_list_head = { "", "", true, NULL };
    bind_mount_pair* bind_directly_list_iter = &bind_directly_list_head;

    bind_mount_pair bind_top_list_head = { "", "", true, NULL };
    bind_mount_pair* bind_top_list_iter = &bind_top_list_head;

    bind_mount_pair exclude_list_head = { "", "", true, NULL };
    bind_mount_pair* exclude_list_iter = &exclude_list_head;

#define EQARG(STR) streq(argv[index],STR)
#define WARN(STR) if(index + 1 >= argc) {\
                    fprintf(stderr, "One more argument is needed for " #STR "."\
                    "You also need to specify the program you want to run.\n");\
                    return EXIT_FAILURE;\
                  }
#define ARG(STR, ITER, FUNC) if(EQARG(STR)) {\
                                WARN(STR); \
                                use_default = false; \
                                iter = ITER;\
                                new_list = FUNC(argv[++index]);\
                            }

    for(index = 1; index < argc; index++){
        if(argv[index][0] != '-')break;

        bind_mount_pair** iter = NULL;
        bind_mount_pair* new_list = NULL;
        if(EQARG("--dry-run")){
            dry_run = true;
            continue;
        } else if(EQARG("--run-in")) {
            WARN("--run-in")
            if(working_dir != NULL){
                fprintf(stderr, "\"--run-in\" should be specified at most once.");
            }
            working_dir = argv[++index];
        }
        else ARG("--bind", &bind_directly_list_iter, bind_opt)
        else ARG("--bind-top", &bind_top_list_iter, bind_top_opt)
        else ARG("--bind-temp", &bind_directly_list_iter, bind_temp_opt)
        else ARG("--exclude", &exclude_list_iter, exclude_opt)
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[index]);
            exit(1);
        }
        if(iter != NULL && new_list != NULL){
            (*iter)->next = new_list;
            while((*iter)->next != NULL){
                *iter = (*iter)->next;
            }
        }
    }

    if(use_default){
        bind_top_list_head.next = bind_top_opt(strdup("/,/"));
        char* home = getenv("HOME");
        if(home != NULL){
            exclude_list_head.next = exclude_opt(strdup("/home"));
            bind_directly_list_head.next = bind_temp_opt(home);
        }
    }

    exclude(&bind_top_list_head, &exclude_list_head);

    bind_mount_pair merged_head = { "", "", true, NULL };
    bind_mount_pair* merged_iter = &merged_head;
    merged_iter->next = bind_directly_list_head.next;
    while(merged_iter->next != NULL){
        merged_iter = merged_iter->next;
    }
    merged_iter->next = bind_top_list_head.next;
    sort_by_hierarchy(&merged_head);

    char* temp_root = mkdtemp(strdup("/tmp/run-in-fsns-XXXXXX"));
    if(pipe(pipe_fd) < 0)assert_perror(errno);
    pid_t child = syscall (SYS_clone, SIGCHLD | CLONE_NEWNS | CLONE_NEWUSER, NULL, NULL, NULL);

    switch (child){
        case 0:
            do_mount(temp_root, merged_head.next);
            ERR(MAY_DRY_RUN(chdir, temp_root));
            ERR(MAY_DRY_RUN(chroot, temp_root));

            if(working_dir == NULL)working_dir = realpath(getenv("HOME"), NULL);
            if(working_dir == NULL)working_dir = "/";
            MAY_DRY_RUN(chdir, working_dir);
            break;
        case -1:
            rm_rf(temp_root);
	        fprintf (stderr, "%s: error: 'clone' failed: %m\n", argv[0]);
            return EXIT_FAILURE;
        default:
            if(!dry_run){
	            disallow_setgroups (child);
	            write_id_map (child, "uid_map", getuid ());
	            write_id_map (child, "gid_map", getgid ());
            }

            close(pipe_fd[1]);
	        int status;
	        waitpid (child, &status, 0);
	        chdir ("/");			  /* avoid EBUSY */
	        rm_rf (temp_root);
	        free (temp_root);
	        exit (status);
    }

    char* default_args[2] = { "/bin/sh", NULL };
    char* command = index >= argc ? default_args[0] : argv[index];
    char** arguments = index >= argc ? default_args : &argv[index];
    
    char ch;

    /* Wait until the parent has updated the UID and GID mappings. See
       the comment in main(). We wait for end of file on a pipe that will
       be closed by the parent process once it has updated the mappings. */

    close(pipe_fd[1]);    /* Close our descriptor for the write end
                                   of the pipe so that we see EOF when
                                   parent closes its descriptor */
    if (read(pipe_fd[0], &ch, 1) != 0) {
        fprintf(stderr, "Failure in child: read from pipe returned != 0\n");
        exit(EXIT_FAILURE);
    }

    ERR(MAY_DRY_RUN(execvp, command, arguments));
    return EXIT_SUCCESS;
}
