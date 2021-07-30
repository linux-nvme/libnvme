// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

%module nvme

%include "exception.i"

%allowexception;

%rename(root)      nvme_root;
%rename(host)      nvme_host;
%rename(ctrl)      nvme_ctrl;
%rename(subsystem) nvme_subsystem;
%rename(ns)        nvme_ns;

/* There is a name conflict. In tree.h, the function nvme_ctrl_identify() is
 * already defined, which means that we can't define nvme_ctrl::identify()
 * when we extend "struct nvme_ctrl" (see "%extend nvme_ctrl" below).
 * Instead, we define the method as nvme_ctrl::__identify__() to avoid the
 * conflict. Fortunately, we can work around the problem with SWIG's %rename()
 * command so that in the generated Python code the method will be named
 * identify() and not __identify__() as hown here:
 *
 *    def identify(self) -> "struct nvme_id_ctrl *":
 *        return _nvme.ctrl_identify(self)
 */
%rename(identify)  __identify__;

%{
#include <assert.h>
#include <ccan/list/list.h>
#include "nvme/tree.h"
#include "nvme/fabrics.h"
#include "nvme/private.h"
#include "nvme/log.h"

static int host_iter_err = 0;
static int subsys_iter_err = 0;
static int ctrl_iter_err = 0;
static int ns_iter_err = 0;
static int connect_err = 0;
static int discover_err = 0;
static int identify_err = 0;
%}

%inline %{
  struct host_iter {
    struct nvme_root *root;
    struct nvme_host *pos;
  };

  struct subsystem_iter {
    struct nvme_host *host;
    struct nvme_subsystem *pos;
  };

  struct ctrl_iter {
    struct nvme_subsystem *subsystem;
    struct nvme_ctrl *pos;
  };

  struct ns_iter {
    struct nvme_subsystem *subsystem;
    struct nvme_ctrl *ctrl;
    struct nvme_ns *pos;
  };
%}

%exception host_iter::__next__ {
  assert(!host_iter_err);
  $action
  if (host_iter_err) {
    host_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception subsystem_iter::__next__ {
  assert(!subsys_iter_err);
  $action
  if (subsys_iter_err) {
    subsys_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception ctrl_iter::__next__ {
  assert(!ctrl_iter_err);
  $action
  if (ctrl_iter_err) {
    ctrl_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception ns_iter::__next__ {
  assert(!ns_iter_err);
  $action
  if (ns_iter_err) {
    ns_iter_err = 0;
    PyErr_SetString(PyExc_StopIteration, "End of list");
    return NULL;
  }
}

%exception nvme_ctrl::connect {
  $action
  if (connect_err == 1) {
    connect_err = 0;
    SWIG_exception(SWIG_AttributeError, "Existing controller connection");
  } else if (connect_err) {
    connect_err = 0;
    if (nvme_log_message)
      SWIG_exception(SWIG_RuntimeError, nvme_log_message);
    else
      SWIG_exception(SWIG_RuntimeError, "Connect failed");
  }
}

%exception nvme_ctrl::discover {
  $action
  if (discover_err) {
    discover_err = 0;
    SWIG_exception(SWIG_RuntimeError,"Discover failed");
  }
}

%exception nvme_ctrl::__identify__ {
  identify_err = 0;
  $action
  if (identify_err) SWIG_exception(SWIG_RuntimeError,"Identify failed");
}

#include "tree.h"
#include "fabrics.h"

%typemap(in) struct nvme_fabrics_config * ($*1_type temp) {
  Py_ssize_t pos = 0;
  PyObject *key, *value;
  memset(&temp, 0, sizeof(temp));
  temp.tos = -1;
  temp.ctrl_loss_tmo = NVMF_DEF_CTRL_LOSS_TMO;
  while (PyDict_Next($input, &pos, &key, &value)) {
    if (!PyUnicode_CompareWithASCIIString(key, "nr_io_queues"))
      temp.nr_io_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "reconnect_delay"))
      temp.reconnect_delay = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "ctrl_loss_tmo"))
      temp.ctrl_loss_tmo = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "keep_alive_tmo"))
      temp.keep_alive_tmo = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "nr_write_queues"))
      temp.nr_write_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "nr_poll_queues"))
      temp.nr_poll_queues = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "tos"))
      temp.tos = PyLong_AsLong(value);
    if (!PyUnicode_CompareWithASCIIString(key, "duplicate_connect"))
      temp.duplicate_connect = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "disable_sqflow"))
      temp.disable_sqflow = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "hdr_digest"))
      temp.hdr_digest = PyObject_IsTrue(value) ? true : false;
    if (!PyUnicode_CompareWithASCIIString(key, "data_digest"))
      temp.data_digest = PyObject_IsTrue(value) ? true : false;
  }
  $1 = &temp;
 };

%typemap(out) uint8_t [8] {
  $result = PyBytes_FromStringAndSize((char *)$1, 8);
};

%typemap(out) uint8_t [16] {
  $result = PyBytes_FromStringAndSize((char *)$1, 16);
};

%typemap(newfree) struct nvmf_discovery_log * {
   if ($1) free($1);
}

%typemap(out) struct nvmf_discovery_log * {
  struct nvmf_discovery_log *log = $1;
  int numrec = log? log->numrec : 0, i;
  PyObject *obj = PyList_New(numrec);
  if (!obj)
    return NULL;
  for (i = 0; i < numrec; i++) {
    struct nvmf_disc_log_entry *e = &log->entries[i];
    PyObject *entry = PyDict_New(), *val;

    switch (e->trtype) {
    case NVMF_TRTYPE_UNSPECIFIED:
      val = PyUnicode_FromString("unspecified");
      break;
    case NVMF_TRTYPE_RDMA:
      val = PyUnicode_FromString("rdma");
      break;
    case NVMF_TRTYPE_FC:
      val = PyUnicode_FromString("fc");
      break;
    case NVMF_TRTYPE_TCP:
      val = PyUnicode_FromString("tcp");
      break;
    case NVMF_TRTYPE_LOOP:
      val = PyUnicode_FromString("loop");
      break;
    default:
      val = PyLong_FromLong(e->trtype);
    }
    PyDict_SetItemString(entry, "trtype", val);
    switch (e->adrfam) {
    case NVMF_ADDR_FAMILY_PCI:
      val = PyUnicode_FromString("pci");
      break;
    case NVMF_ADDR_FAMILY_IP4:
      val = PyUnicode_FromString("ipv4");
      break;
    case NVMF_ADDR_FAMILY_IP6:
      val = PyUnicode_FromString("ipv6");
      break;
    case NVMF_ADDR_FAMILY_IB:
      val = PyUnicode_FromString("infiniband");
      break;
    case NVMF_ADDR_FAMILY_FC:
      val = PyUnicode_FromString("fc");
      break;
    default:
      val = PyLong_FromLong(e->adrfam);
    }
    PyDict_SetItemString(entry, "adrfam", val);
    val = PyUnicode_FromString(e->traddr);
    PyDict_SetItemString(entry, "traddr", val);
    val = PyUnicode_FromString(e->trsvcid);
    PyDict_SetItemString(entry, "trsvcid", val);
    val = PyUnicode_FromString(e->subnqn);
    PyDict_SetItemString(entry, "subnqn", val);
    switch (e->subtype) {
    case NVME_NQN_DISC:
      val = PyUnicode_FromString("discovery");
      break;
    case NVME_NQN_NVME:
      val = PyUnicode_FromString("nvme");
      break;
    default:
      val = PyLong_FromLong(e->subtype);
    }
    PyDict_SetItemString(entry, "subtype", val);
    switch (e->treq) {
    case NVMF_TREQ_NOT_SPECIFIED:
      val = PyUnicode_FromString("not specified");
      break;
    case NVMF_TREQ_REQUIRED:
      val = PyUnicode_FromString("required");
      break;
    case NVMF_TREQ_NOT_REQUIRED:
      val = PyUnicode_FromString("not required");
      break;
    case NVMF_TREQ_DISABLE_SQFLOW:
      val = PyUnicode_FromString("disable sqflow");
      break;
    default:
      val = PyLong_FromLong(e->treq);
    }
    PyDict_SetItemString(entry, "treq", val);
    val = PyLong_FromLong(e->portid);
    PyDict_SetItemString(entry, "portid", val);
    val = PyLong_FromLong(e->cntlid);
    PyDict_SetItemString(entry, "cntlid", val);
    val = PyLong_FromLong(e->asqsz);
    PyDict_SetItemString(entry, "asqsz", val);
    PyList_SetItem(obj, i, entry);
  }
  $result = obj;
 };

%{
#define SUCCESS_OR_GETOUT(_val, _label) do { if ((_val) != 0) goto _label; } while (0)
int add_long_to_dict(PyObject * dict, const char * key, long v)
{
        int       ret = -1;
        PyObject *val = PyLong_FromLong(v);
        if (!val)
                return -1;

        /* PyDict_SetItemString does not steal the reference to tmp_p.
         * So one must decrement the ref count. */
        ret = PyDict_SetItemString(dict, key, val);
        Py_CLEAR(val);
        return ret;
}

int add_string_to_dict(PyObject * dict, const char * key, const char * s, size_t maxlen)
{
        int       ret = -1;
        PyObject *val = NULL;
        size_t    len = maxlen;
        while ((len > 0) && ((s[len-1] == '\0') || (s[len-1] == ' '))) // strip trailing spaces
                len--;

        val = PyUnicode_FromStringAndSize(s, len);

        /* PyDict_SetItemString does not steal the reference to tmp_p.
         * So one must decrement the ref count. */
        ret = PyDict_SetItemString(dict, key, val);
        Py_CLEAR(val);
        return ret;
}

int add_bytearray_to_dict(PyObject * dict, const char * key, const unsigned char * b, size_t len)
{
        PyObject * val = PyByteArray_FromStringAndSize((const char *)b, len);
        int        ret = PyDict_SetItemString(dict, key, val);
        Py_CLEAR(val);
        return ret;
}

PyObject * get_psd_dict(struct nvme_id_psd * psd)
{
        PyObject *dict = PyDict_New();
        if (dict == NULL)
                goto cleanup;

        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mp", psd->mp), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "flags", psd->flags), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "enlat", psd->enlat), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "exlat", psd->exlat), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rrt", psd->rrt), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rrl", psd->rrl), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rwt", psd->rwt), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rwl", psd->rwl), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "idlp", psd->idlp), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ips", psd->ips), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "actp", psd->actp), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "apw", psd->apw), cleanup);
        SUCCESS_OR_GETOUT(add_long_to_dict(dict, "aps", psd->aps), cleanup);
        return dict;

cleanup:
        Py_CLEAR(dict);
        return NULL;
}
%};

%typemap(newfree) struct nvme_id_ctrl * {
   if ($1) free($1);
}

%typemap(out) struct nvme_id_ctrl * {
   struct nvme_id_ctrl *id   = $1;
   PyObject            *dict = NULL;
   PyObject            *psd  = NULL;
   int                  ret  = 0;
   size_t               i    = 0;

   if (id == NULL)
     goto cleanup;

   dict = PyDict_New();
   if (dict == NULL)
     goto cleanup;

   psd = PyList_New(32);
   if (psd == NULL)
     goto cleanup;

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "vid", id->vid), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ssvid", id->ssvid), cleanup);

   SUCCESS_OR_GETOUT(add_string_to_dict(dict, "sn", id->sn, sizeof(id->sn)), cleanup);
   SUCCESS_OR_GETOUT(add_string_to_dict(dict, "mn", id->mn, sizeof(id->mn)), cleanup);
   SUCCESS_OR_GETOUT(add_string_to_dict(dict, "fr", id->fr, sizeof(id->fr)), cleanup);

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rab", id->rab), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ieee", (((unsigned)id->ieee[0]) << 16) | ((unsigned)id->ieee[1]) << 8) | (unsigned)id->ieee[2], cleanup);

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "cmic", id->cmic), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mdts", id->mdts), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "cntlid", id->cntlid), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ver", id->ver), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rtd3r", id->rtd3r), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rtd3e", id->rtd3e), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "oaes", id->oaes), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ctratt", id->ctratt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rrls", id->rrls), cleanup);
   switch (id->cntrltype) {
   case NVME_CTRL_CNTRLTYPE_IO:
     SUCCESS_OR_GETOUT(add_string_to_dict(dict, "cntrltype", "I/O", strlen("I/O")), cleanup);
     break;
   case NVME_CTRL_CNTRLTYPE_DISCOVERY:
     SUCCESS_OR_GETOUT(add_string_to_dict(dict, "cntrltype", "Discovery", strlen("Discovery")), cleanup);
     break;
   case NVME_CTRL_CNTRLTYPE_ADMIN:
     SUCCESS_OR_GETOUT(add_string_to_dict(dict, "cntrltype", "Admin", strlen("Admin")), cleanup);
     break;
   default:
     SUCCESS_OR_GETOUT(add_long_to_dict(dict, "cntrltype", id->cntrltype), cleanup);
   }

   SUCCESS_OR_GETOUT(add_bytearray_to_dict(dict, "fguid", id->fguid, sizeof(id->fguid)), cleanup);

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "crdt1", id->crdt1), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "crdt2", id->crdt3), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "crdt3", id->crdt3), cleanup);

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "nvmsr", id->nvmsr), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "vwci", id->vwci), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mec", id->mec), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "oacs", id->oacs), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "acl", id->acl), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "aerl", id->aerl), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "frmw", id->frmw), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "lpa", id->lpa), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "elpe", id->elpe), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "npss", id->npss), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "avscc", id->avscc), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "apsta", id->apsta), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "wctemp", id->wctemp), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "cctemp", id->cctemp), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mtfa", id->mtfa), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "hmpre", id->hmpre), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "hmmin", id->hmmin), cleanup);
   SUCCESS_OR_GETOUT(add_bytearray_to_dict(dict, "tnvmcap", id->tnvmcap, sizeof(id->tnvmcap)), cleanup);
   SUCCESS_OR_GETOUT(add_bytearray_to_dict(dict, "unvmcap", id->unvmcap, sizeof(id->unvmcap)), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "rpmbs", id->rpmbs), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "edstt", id->edstt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "dsto", id->dsto), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "fwug", id->fwug), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "kas", id->kas), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "hctma", id->hctma), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mntmt", id->mntmt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mxtmt", id->mxtmt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "sanicap", id->sanicap), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "hmminds", id->hmminds), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "hmmaxd", id->hmmaxd), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "nsetidmax", id->nsetidmax), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "endgidmax", id->endgidmax), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "anatt", id->anatt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "anacap", id->anacap), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "anagrpmax", id->anagrpmax), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "nanagrpid", id->nanagrpid), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "pels", id->pels), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "sqes", id->sqes), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "cqes", id->cqes), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "maxcmd", id->maxcmd), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "nn", id->nn), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "oncs", id->oncs), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "fuses", id->fuses), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "fna", id->fna), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "vwc", id->vwc), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "awun", id->awun), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "awupf", id->awupf), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "icsvscc", id->icsvscc), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "nwpc", id->nwpc), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "acwu", id->acwu), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "sgls", id->sgls), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "mnan", id->mnan), cleanup);

   SUCCESS_OR_GETOUT(add_string_to_dict(dict, "subnqn", id->subnqn, sizeof(id->subnqn)), cleanup);

   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ioccsz", id->ioccsz), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "iorcsz", id->iorcsz), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "icdoff", id->icdoff), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "fcatt", id->fcatt), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "msdbd", id->msdbd), cleanup);
   SUCCESS_OR_GETOUT(add_long_to_dict(dict, "ofcs", id->ofcs), cleanup);

   for (i = 0; i < 32; i++)
   {
     PyObject * obj = get_psd_dict(&id->psd[i]);
     if (obj == NULL)
       goto cleanup;
     PyList_SET_ITEM(psd, i, obj);
   }
   ret = PyDict_SetItemString(dict, "psd", psd);
   if (ret == -1)
     goto cleanup;

   $result = dict;

cleanup:
   if ($result != dict) {
     Py_CLEAR(dict);
     Py_CLEAR(psd);
   }
};

struct nvme_root {
  %immutable config_file;
  char *config_file;
};

struct nvme_host {
  %immutable hostnqn;
  %immutable hostid;
  char *hostnqn;
  char *hostid;
};

struct nvme_subsystem {
  %immutable subsysnqn;
  %immutable model;
  %immutable serial;
  %immutable firmware;
  char *subsysnqn;
  char *model;
  char *serial;
  char *firmware;
};

struct nvme_ctrl {
  %immutable transport;
  %immutable subsysnqn;
  %immutable traddr;
  %immutable host_traddr;
  %immutable trsvcid;
  %immutable address;
  %immutable firmware;
  %immutable model;
  %immutable numa_node;
  %immutable queue_count;
  %immutable serial;
  %immutable sqsize;
  char *transport;
  char *subsysnqn;
  char *traddr;
  char *host_traddr;
  char *trsvcid;
  char *address;
  char *firmware;
  char *model;
  char *numa_node;
  char *queue_count;
  char *serial;
  char *sqsize;
};

struct nvme_ns {
  %immutable nsid;
  %immutable eui64;
  %immutable nguid;
  %immutable uuid;
  unsigned int nsid;
  uint8_t eui64[8];
  uint8_t nguid[16];
  uint8_t uuid[16];
};

%extend nvme_root {
  nvme_root(const char *config_file = NULL) {
    nvme_log_level = LOG_ERR;
    return nvme_scan(config_file);
  }
  ~nvme_root() {
    nvme_free_tree($self);
  }
  void log_level(const char *level) {
    if (!strcmp(level,"debug"))
      nvme_log_level = LOG_DEBUG;
    else if (!strcmp(level, "info"))
      nvme_log_level = LOG_INFO;
    else if (!strcmp(level, "notice"))
      nvme_log_level = LOG_NOTICE;
    else if (!strcmp(level, "warning"))
      nvme_log_level = LOG_WARNING;
    else if (!strcmp(level, "err"))
      nvme_log_level = LOG_ERR;
    else if (!strcmp(level, "crit"))
      nvme_log_level = LOG_CRIT;
    else if (!strcmp(level, "alert"))
      nvme_log_level = LOG_ALERT;
    else if (!strcmp(level, "emerg"))
      nvme_log_level = LOG_EMERG;
  }
  struct nvme_host *hosts() {
    return nvme_first_host($self);
  }
  void refresh_topology() {
    nvme_refresh_topology($self);
  }
  void update_config() {
    nvme_update_config($self);
  }
}

%extend host_iter {
  struct host_iter *__iter__() {
    return $self;
  }
  struct nvme_host *__next__() {
    struct nvme_host *this = $self->pos;

    if (!this) {
      host_iter_err = 1;
      return NULL;
    }
    $self->pos = nvme_next_host($self->root, this);
    return this;
  }
}

%extend nvme_host {
  nvme_host(struct nvme_root *r, const char *hostnqn = NULL,
	    const char *hostid = NULL) {
    if (!hostnqn)
      return nvme_default_host(r);
    return nvme_lookup_host(r, hostnqn, hostid);
  }
  ~nvme_host() {
    nvme_free_host($self);
  }
  char *__str__() {
    static char tmp[2048];

    sprintf(tmp, "nvme_host(%s,%s)", $self->hostnqn, $self->hostid);
    return tmp;
  }
  struct host_iter __iter__() {
    struct host_iter ret = { .root = nvme_host_get_root($self),
				     .pos = $self };
    return ret;
  }
  struct nvme_subsystem *subsystems() {
    return nvme_first_subsystem($self);
  }
}

%extend subsystem_iter {
  struct subsystem_iter *__iter__() {
    return $self;
  }
  struct nvme_subsystem *__next__() {
    struct nvme_subsystem *this = $self->pos;

    if (!this) {
      subsys_iter_err = 1;
      return NULL;
    }
    $self->pos = nvme_next_subsystem($self->host, this);
    return this;
  }
}

%extend ns_iter {
  struct ns_iter *__iter__() {
    return $self;
  }
  struct nvme_ns *__next__() {
    struct nvme_ns *this = $self->pos;

    if (!this) {
      ns_iter_err = 1;
      return NULL;
    }
    if ($self->ctrl)
      $self->pos = nvme_ctrl_next_ns($self->ctrl, this);
    else
      $self->pos = nvme_subsystem_next_ns($self->subsystem, this);
    return this;
  }
}

%extend nvme_subsystem {
  nvme_subsystem(struct nvme_host *host, const char *subsysnqn,
		 const char *name = NULL) {
    return nvme_lookup_subsystem(host, name, subsysnqn);
  }
  ~nvme_subsystem() {
    nvme_free_subsystem($self);
  }
  char *__str__() {
    static char tmp[1024];

    sprintf(tmp, "nvme_subsystem(%s,%s)", $self->name,$self->subsysnqn);
    return tmp;
  }
  struct subsystem_iter __iter__() {
    struct subsystem_iter ret = { .host = nvme_subsystem_get_host($self),
				       .pos = $self };
    return ret;
  }
  struct nvme_ctrl *controllers() {
    return nvme_subsystem_first_ctrl($self);
  }
  struct nvme_ns *namespaces() {
    return nvme_subsystem_first_ns($self);
  }
  %immutable name;
  const char *name;
  %immutable host;
  struct nvme_host *host;
}

%{
  const char *nvme_subsystem_name_get(struct nvme_subsystem *s) {
    return nvme_subsystem_get_name(s);
  }
  struct nvme_host *nvme_subsystem_host_get(struct nvme_subsystem *s) {
    return nvme_subsystem_get_host(s);
  }
%};

%extend ctrl_iter {
  struct ctrl_iter *__iter__() {
    return $self;
  }
  struct nvme_ctrl *__next__() {
    struct nvme_ctrl *this = $self->pos;

    if (!this) {
      ctrl_iter_err = 1;
      return NULL;
    }
    $self->pos = nvme_subsystem_next_ctrl($self->subsystem, this);
    return this;
  }
}

%extend nvme_ctrl {
  nvme_ctrl(const char *subsysnqn, const char *transport,
	    const char *traddr = NULL, const char *host_traddr = NULL,
	    const char *host_iface = NULL, const char *trsvcid = NULL) {
    return nvme_create_ctrl(subsysnqn, transport, traddr,
			    host_traddr, host_iface, trsvcid);
  }
  ~nvme_ctrl() {
    nvme_free_ctrl($self);
  }
  void connect(struct nvme_host *h, struct nvme_fabrics_config *cfg = NULL) {
    int ret;
    const char *dev;

    dev = nvme_ctrl_get_name($self);
    if (dev && !cfg->duplicate_connect) {
      connect_err = 1;
      return;
    }
    ret = nvmf_add_ctrl(h, $self, cfg, cfg->disable_sqflow);
    if (ret < 0) {
      connect_err = 2;
      return;
    }
  }
  bool connected() {
    return nvme_ctrl_get_name($self) != NULL;
  }
  void rescan() {
    nvme_rescan_ctrl($self);
  }
  void disconnect() {
    nvme_disconnect_ctrl($self);
  }

  %newobject discover;
  struct nvmf_discovery_log *discover(int max_retries = 6) {
    struct nvmf_discovery_log *logp = NULL;
    int ret = 0;
    ret = nvmf_get_discovery_log($self, &logp, max_retries);
    if (ret < 0) {
      discover_err = 1;
      return NULL;
    }
    return logp;
  }

  /* Note about the name __identify__: this dunder method is to workaround a
     name conflict with function "nvme_ctrl_identify()" defined in tree.h.
     We use the %rename command (at the top of this file) to rename
     "__identify__" to "identify" in the generated Python class. */
  %newobject __identify__;
  struct nvme_id_ctrl * __identify__() {
    struct nvme_id_ctrl * id = (struct nvme_id_ctrl *)calloc(1, sizeof(struct nvme_id_ctrl));
    if (nvme_ctrl_identify($self, id) < 0)
    {
      free(id);
      identify_err = 1;
      return NULL;
    }
    return id;
  }
  char *__str__() {
    static char tmp[1024];

    if ($self->address)
      sprintf(tmp, "nvme_ctrl(transport=%s,%s)", $self->transport,
	      $self->address);
    else
      sprintf(tmp, "nvme_ctrl(transport=%s)", $self->transport);
    return tmp;
  }
  struct ctrl_iter __iter__() {
    struct ctrl_iter ret = { .subsystem = nvme_ctrl_get_subsystem($self),
				  .pos = $self };
    return ret;
  }
  struct nvme_ns *namespaces() {
    return nvme_ctrl_first_ns($self);
  }
  %immutable name;
  const char *name;
  %immutable subsystem;
  struct nvme_subsystem *subsystem;
  %immutable state;
  const char *state;
}

%{
  const char *nvme_ctrl_name_get(struct nvme_ctrl *c) {
    return nvme_ctrl_get_name(c);
  }
  struct nvme_subsystem *nvme_ctrl_subsystem_get(struct nvme_ctrl *c) {
    return nvme_ctrl_get_subsystem(c);
  }
  const char *nvme_ctrl_state_get(struct nvme_ctrl *c) {
    return nvme_ctrl_get_state(c);
  }
%};

%extend nvme_ns {
  nvme_ns(struct nvme_subsystem *s, unsigned int nsid) {
    return nvme_subsystem_lookup_namespace(s, nsid);
  }
  ~nvme_ns() {
    nvme_free_ns($self);
  }
  char *__str__() {
    static char tmp[1024];

    sprintf(tmp, "nvme_ns(%u)", $self->nsid);
    return tmp;
  }
  struct ns_iter __iter__() {
    struct ns_iter ret = { .ctrl = nvme_ns_get_ctrl($self),
				.subsystem = nvme_ns_get_subsystem($self),
				.pos = $self };
    return ret;
  }
  %immutable name;
  const char *name;
}

%{
  const char *nvme_ns_name_get(struct nvme_ns *n) {
    return nvme_ns_get_name(n);
  }
%};

