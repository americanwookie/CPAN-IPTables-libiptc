#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libiptc/libiptc.h>
#include <errno.h>

#include "const-c.inc"

#define ERROR_SV perl_get_sv("!", 0)
#define SET_ERRSTR(format...) sv_setpvf(ERROR_SV, ##format)
#define SET_ERRNUM(value) sv_setiv(ERROR_SV, (IV)value)

#define ERRSTR_NULL_HANDLE "ERROR: IPTables handle==NULL, forgot to call init?"

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
    }
  OUTPUT:
    RETVAL


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
# Stuff...
##########################################


void
DESTROY(self)
    IPTables::libiptc &self
  CODE:
    if(self) {
	if(*self) iptc_free(self);
	free(self);
    }
