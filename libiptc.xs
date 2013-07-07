#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libiptc/libiptc.h>
#include <include/iptables.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>

#include "const-c.inc"

#define ERROR_SV perl_get_sv("!", 0)
#define SET_ERRSTR(format...) sv_setpvf(ERROR_SV, ##format)
#define SET_ERRNUM(value) sv_setiv(ERROR_SV, (IV)value)

#define ERRSTR_NULL_HANDLE "ERROR: IPTables handle==NULL, forgot to call init?"

extern const char *program_name, *program_version;
extern char *lib_dir;

typedef iptc_handle_t* IPTables__libiptc;

MODULE = IPTables::libiptc		PACKAGE = IPTables::libiptc

INCLUDE: const-xs.inc


IPTables::libiptc
init(tablename)
    char * tablename
  PREINIT:
    iptc_handle_t handle;
  CODE:
    handle  = iptc_init(tablename);
    if (handle == NULL) {
	RETVAL  = NULL;
	SET_ERRNUM(errno);
	SET_ERRSTR("%s", iptc_strerror(errno));
	SvIOK_on(ERROR_SV);
    } else {
	RETVAL  = malloc(sizeof(iptc_handle_t));
	*RETVAL = handle;
	# TODO: Lock /var/lock/iptables_tablename
    }
  OUTPUT:
    RETVAL


int
commit(self)
    IPTables::libiptc self
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_commit(self);
	if(!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
	*self = NULL;
	# TODO: UnLock /var/lock/iptables_tablename
    }
  OUTPUT:
    RETVAL


void
DESTROY(self)
    IPTables::libiptc &self
  CODE:
    if(self) {
	if(*self) iptc_free(self);
	free(self);
    }
    # TODO: UnLock /var/lock/iptables_tablename


##########################################
#  Chain operations
##########################################

int
is_chain(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if   (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else RETVAL = iptc_is_chain(chain, *self);
  OUTPUT:
    RETVAL


int
create_chain(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_create_chain(chain, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


int
delete_chain(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_delete_chain(chain, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


int
rename_chain(self, old_name, new_name)
    IPTables::libiptc self
    ipt_chainlabel    old_name
    ipt_chainlabel    new_name
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_rename_chain(old_name, new_name, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


int
builtin(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_builtin(chain, *self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


int
get_references(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	if (!iptc_get_references(&RETVAL, chain, self)) {
	    RETVAL  = -1;
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


##########################################
# Rules/Entries affecting a full chain
##########################################

int
flush_entries(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_flush_entries(chain, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


int
zero_entries(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = iptc_zero_entries(chain, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL

##########################################
# Listing related
##########################################

void
list_chains(self)
    IPTables::libiptc self
  PREINIT:
    char * chain;
    SV *   sv;
    int    count = 0;
  PPCODE:
    sv = ST(0);
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	chain = (char *)iptc_first_chain(self);
	while(chain) {
	    count++;
	    if (GIMME_V == G_ARRAY)
		XPUSHs(sv_2mortal(newSVpv(chain, 0)));
	    chain = (char *)iptc_next_chain(self);
	}
	if (GIMME_V == G_SCALAR)
	    XPUSHs(sv_2mortal(newSViv(count)));
    }


void
list_rules_IPs(self, type, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
    char *            type
  PREINIT:
    SV *   sv;
    int    count = 0;
    struct ipt_entry *entry;
    int    the_type;
    char   buf[100]; /* I should be enough with only 32 chars */
    static char * errmsg = "Wrong listing type requested.";
  PPCODE:
    sv = ST(0);
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	if(iptc_is_chain(chain, *self)) {
	    entry = (struct ipt_entry *)iptc_first_rule(chain, self);

	    /* Parse what type was requested */
	    if      (strcasecmp(type, "dst") == 0) the_type = 'd';
	    else if (strcasecmp(type, "src") == 0) the_type = 's';
	    else croak(errmsg);

	    while(entry) {
		count++;
 		if (GIMME_V == G_ARRAY) {

		    switch (the_type) {
		    case 'd':
			sprintf(buf,"%s",(char*)addr_to_dotted(&(entry->ip.dst)));
			strcat(buf, (char*) mask_to_dotted(&(entry->ip.dmsk)));
			sv = newSVpv(buf, 0);
		        break;
		    case 's':
			sprintf(buf,"%s",(char*)addr_to_dotted(&(entry->ip.src)));
			strcat(buf, (char*) mask_to_dotted(&(entry->ip.smsk)));
			sv = newSVpv(buf, 0);
		        break;
		    default:
		        croak(errmsg);
		    }
		    XPUSHs(sv_2mortal(sv));
		}
		entry = (struct ipt_entry *)iptc_next_rule(entry, self);
	    }
	    if (GIMME_V == G_SCALAR)
		XPUSHs(sv_2mortal(newSViv(count)));
	} else {
	    XSRETURN_UNDEF;
	}
    }

SV *
list_rules(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  INIT:
    AV * results;
    AV * matches;
    int    count = 0;
    int    i;
    struct ipt_entry *entry;
    struct protoent *pent;
    char   buf[100]; /* I should be enough with only 32 chars */
    static char * errmsg = "Something vague has gone wrong.";
    struct ipt_entry_target *t;
    results = (AV *)sv_2mortal((SV *)newAV());
    matches = (AV *)sv_2mortal((SV *)newAV());
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
        if(iptc_is_chain(chain, *self)) {
            entry = (struct ipt_entry *)iptc_first_rule(chain, self);

            while(entry) {
                count++;
                if (GIMME_V == G_ARRAY) {
                    HV * rh;
                    rh = (HV *)sv_2mortal((SV *)newHV());

                    //Source -- TODO check for inversion
                    sprintf(buf,"%s%s",(char*)addr_to_dotted(&(entry->ip.src)),
                                       (char*)mask_to_dotted(&(entry->ip.smsk)));
                    hv_store(rh, "src", 3, newSVpv(buf, 0), 0);

                    //Destination -- TODO check for inversion
                    sprintf(buf,"%s%s",(char*)addr_to_dotted(&(entry->ip.dst)),
                                       (char*)mask_to_dotted(&(entry->ip.dmsk)));
                    hv_store(rh, "dst", 3, newSVpv(buf, 0), 0);

                    //Input interface -- TODO check for inversion
                    //Taken verabatim from iptables-save.c
                    sprintf(buf, "");
                    for (i = 0; i < IFNAMSIZ; i++) {
                        if (entry->ip.iniface_mask[i] != 0) {
                            if (entry->ip.iniface[i] != '\0') {
                                snprintf(buf + strlen(buf), 100, "%c", entry->ip.iniface[i]);
                            }
                        } else {
                            /* we can access iface[i-1] here, because
                             * a few lines above we make sure that mask[0] != 0 */
                            if (entry->ip.iniface[i-1] != '\0')
                                strcat(buf, "+");
                            break;
                        }
                    }
                    hv_store(rh, "iniface", 7, newSVpv(buf, 0), 0);

                    //Input interface -- TODO check for inversion
                    //Adapted from iptables-save.c
                    sprintf(buf, "");
                    for (i = 0; i < IFNAMSIZ; i++) {
                        if (entry->ip.outiface_mask[i] != 0) {
                            if (entry->ip.outiface[i] != '\0')
                                snprintf(buf + strlen(buf), 100 - strlen(buf), "%c", entry->ip.outiface[i]);
                        } else {
                            /* we can access iface[i-1] here, because
                             * a few lines above we make sure that mask[0] != 0 */
                            if (entry->ip.outiface[i-1] != '\0')
                                strcat(buf, "+");
                            break;
                        }
                    }
                    hv_store(rh, "outiface", 8, newSVpv(buf, 0), 0);

                    //Protocol -- TODO check for inverstion
                    //Adapted from iptables-save.
                    if (entry->ip.proto) {
                        //iptables-save.c incuded a fall back to use a static table.
                        //I've left that out here at my own peril
                        pent = (struct protoent *)getprotobynumber(entry->ip.proto);
                        if (pent)
                            snprintf(buf, 100, "%s", pent->p_name);
                        else
                            snprintf(buf, 100, "%u", entry->ip.proto);
                    }
                    hv_store(rh, "proto", 5, newSVpv(buf, 0), 0);

                    //Fragments?
                    sprintf(buf, "0");
                    if (entry->ip.flags & IPT_F_FRAG)
			sprintf(buf, "1");
                    hv_store(rh, "fragments_only", 14, newSVpv(buf, 0), 0);

                    //Module fun
                    //So, uhhh, my C skills aren't ready for this. print_match
                    //calls the print (ideally it'd be the save) function
                    //provided by each module. Sadly, that does printf directly
                    //and I have no idea how to capture it TODO
//                    sprintf(buf,"");
//                    if (entry->target_offset) {
//                        IPT_MATCH_ITERATE(entry, print_match, &entry->ip, matches);
//                    }

                    //Target
                    snprintf( buf, 100, "%s", iptc_get_target(entry, self));
                    if (buf && (*buf != '\0'))
#ifdef IPT_F_GOTO
                        snprintf( buf + strlen(buf), 100 - strlen(buf), "%s", entry->ip.flags & IPT_F_GOTO ? " (goto)" : " (jump)");
#else
                        snprintf( buf + strlen(buf), 100 - strlen(buf), "%s", " (jump)");
#endif
                    hv_store(rh, "target", 6, newSVpv(buf, 0), 0);

                    //Additional target information
                    //Same problem as module fun above
                    t = ipt_get_target((struct ipt_entry *)entry);
                    if (t->u.user.name[0]) {
                        struct iptables_target *target
                          = find_target(t->u.user.name, TRY_LOAD);

                        if (!target) {
                            fprintf(stderr, "Can't find library for target `%s'\n",
                                    t->u.user.name);
                            exit(1);
                        }

                        if (0 && target->save)
                            target->save(&entry->ip, t);
                        else {
                            /* If the target size is greater than ipt_entry_target
                            * there is something to be saved, we just don't know
                            * how to print it */
                            if (t->u.target_size !=
                                sizeof(struct ipt_entry_target)) {
                                fprintf(stderr, "Target `%s' is missing "
                                                "save function\n",
                                        t->u.user.name);
                                exit(1);
                            }
                        }
                    }

                    av_push(results, newRV((SV *)rh));
                }
                entry = (struct ipt_entry *)iptc_next_rule(entry, self);
            }
//S            if (GIMME_V == G_SCALAR)
//S                XPUSHs(sv_2mortal(newSViv(count)));
        } else {
//S            XSRETURN_UNDEF;
        }
	RETVAL = newRV((SV *)results);
    }
  OUTPUT:
    RETVAL


##########################################
# Policy related
##########################################

void
get_policy(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  PREINIT:
    struct ipt_counters  counters;
    SV *                 sv;
    char *               policy;
    char *               temp;
  PPCODE:
    sv = ST(0);
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	if((policy = (char *)iptc_get_policy(chain, &counters, self))) {
	    XPUSHs(sv_2mortal(newSVpv(policy, 0)));
	    asprintf(&temp, "%llu", counters.pcnt);
	    XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	    free(temp);
	    asprintf(&temp, "%llu", counters.bcnt);
	    XPUSHs(sv_2mortal(newSVpv(temp, 0)));
	    free(temp);
	} else {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }


void
set_policy(self, chain, policy, pkt_cnt=0, byte_cnt=0)
    IPTables::libiptc self
    ipt_chainlabel    chain
    ipt_chainlabel    policy
    unsigned int      pkt_cnt
    unsigned int      byte_cnt
  PREINIT:
    struct ipt_counters *  counters = NULL;
    struct ipt_counters    old_counters;
    char *                 old_policy;
    char *                 temp;
    int retval;
  PPCODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	if(pkt_cnt && byte_cnt) {
	    counters = malloc(sizeof(struct ipt_counters));
	    counters->pcnt = pkt_cnt;
	    counters->bcnt = byte_cnt;
	}
	/* Read the old policy and counters */
	old_policy = (char *)iptc_get_policy(chain, &old_counters, self);

	retval = iptc_set_policy(chain, policy, counters, self);
	/* Return retval to perl */
	XPUSHs(sv_2mortal(newSViv(retval)));
	if (!retval) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	} else {
	    /* return old policy and counters to perl */
      	    if (old_policy) {
		XPUSHs(sv_2mortal(newSVpv(old_policy, 0)));
		asprintf(&temp, "%llu", old_counters.pcnt);
		XPUSHs(sv_2mortal(newSVpv(temp, 0)));
		free(temp);
		asprintf(&temp, "%llu", old_counters.bcnt);
		XPUSHs(sv_2mortal(newSVpv(temp, 0)));
		free(temp);
	    }
	}
    }
    if(counters) free(counters);


##########################################
# iptables.{h,c,o} related
##########################################

# !!!FUNCTION NOT TESTED!!!
int
iptables_delete_chain(self, chain)
    IPTables::libiptc self
    ipt_chainlabel    chain
  CODE:
    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	RETVAL = delete_chain(chain, 0, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


# int do_command(int argc, char *argv[], char **table,
#                iptc_handle_t *handle);
#
int
iptables_do_command(self, array_ref)
    IPTables::libiptc self
    SV  * array_ref;
  INIT:
    static char * argv[255];
    static char * fake_table[1];
    int argc;      /* number of args */
    int array_len; /* number of array elements */
    int n;

    # Perl type checking
    if ((!SvROK(array_ref))
	|| (SvTYPE(SvRV(array_ref)) != SVt_PVAV)
	|| ((array_len = av_len((AV *)SvRV(array_ref))) < 0))
    {
	XSRETURN_UNDEF;
    }
    #array_len = av_len((AV *)SvRV(array_ref));

  CODE:
    program_name = "perl-to-libiptc";
    program_version = IPTABLES_VERSION;

    lib_dir = getenv("IPTABLES_LIB_DIR");
    if (!lib_dir)
        lib_dir = IPT_LIB_DIR;


    /* Due to getopt parsing in iptables.c
     * argv needs to contain the program name as the first arg */
    argv[0] = program_name;
    argc=1;

    for (n = 0; n <= array_len; n++, argc++) {
	STRLEN l;
	char* str = SvPV(*av_fetch((AV *)SvRV(array_ref), n, 0), l);
	argv[argc] = str;
	# printf("loop:%d str:%s   \targv[%d]=%s\n", n, str, argc, argv[argc]);
    }
    # printf("value of n:%d array_len:%d argc:%d\n", n, array_len, argc);

    if (*self == NULL) croak(ERRSTR_NULL_HANDLE);
    else {
	/* The pointer variable fake_table is needed, because iptables.c
	 * will update it if the "-t" argument is specified.  And infact
	 * its not used if the handle is defined (which is checked above).
	 */
	RETVAL = do_command(argc, argv, &fake_table, self);
	if (!RETVAL) {
	    SET_ERRNUM(errno);
	    SET_ERRSTR("%s", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
	if ( fake_table[0] ) {
	    warn("do_command: Specifying table (%s) has no effect as handle is defined.", fake_table[0]);
	    SET_ERRNUM(ENOTSUP);
	    SET_ERRSTR("Specifying table has no effect (%s).", iptc_strerror(errno));
	    SvIOK_on(ERROR_SV);
	}
    }
  OUTPUT:
    RETVAL


##########################################
# Stuff...
##########################################

