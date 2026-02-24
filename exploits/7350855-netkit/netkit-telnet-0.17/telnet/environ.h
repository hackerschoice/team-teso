void env_define(const char *var, const char *val);
void env_undefine(const char *var);
void env_export(const char *var);
void env_unexport(const char *);
void env_send(const char *);
void env_list(void);
const char *env_getvalue(const char *, int exported_only);

void env_iterate(int *, int exported_only);
const char *env_next(int *, int exported_only);
