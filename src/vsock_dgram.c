/*
 * Copyright (C) 2023 ByteDance
 *
 * This file is part of uperf.
 *
 * uperf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation.
 *
 * uperf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with uperf.  If not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <limits.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef  HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif /*  HAVE_SYS_POLL_H */
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/un.h>
#include <unistd.h>
#include "logging.h"
#include "uperf.h"
#include "flowops.h"
#include "workorder.h"
#include "protocol.h"
#include "generic.h"
#include "vsock.h"

/* Defined in <linux/vm_sockets.h> since Linux 5.8 */
#ifndef VMADDR_CID_LOCAL
#define VMADDR_CID_LOCAL 1
#endif

#define VSOCK_HANDSHAKE "uperf vsock handshake"

typedef struct {
	int		sock;
	int		refcount;
	struct sockaddr_storage addr_info;
} vsock_dgram_private_data;

protocol_t *protocol_vsock_dgram_create(char *host, int port);

static int
set_vsock_dgram_options(int fd, flowop_options_t *f)
{
	if (f == NULL)
		return (0);

	if (f && FO_NONBLOCKING(f)) {
		if (generic_setfd_nonblock(fd) != 0) {
			ulog_warn("non-blocking failed, falling back");
			CLEAR_FO_NONBLOCKING(f);
		}
	}

	return (0);
}

static int
read_one(int fd, char *buffer, int len, struct sockaddr_storage *from)
{
	int ret;
	socklen_t length = (socklen_t)sizeof(struct sockaddr_storage);

	ret = recvfrom(fd, buffer, len, 0, (struct sockaddr *)from, &length);
	if (ret <= 0) {
		if (errno != EWOULDBLOCK)
			uperf_log_msg(UPERF_LOG_ERROR, errno, "recvfrom:");
		return (-1);
	}

	return (ret);
}

static int
write_one(int fd, char *buffer, int len, struct sockaddr *to)
{
	socklen_t length = (socklen_t)sizeof(struct sockaddr_vm);
	return (sendto(fd, buffer, len, 0, to, length));
}

static int
protocol_vsock_dgram_read(protocol_t *p, void *buffer, int n, void *options)
{
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *) p->_protocol_p;
	int ret;
	int nleft;
	int timeout = 0;
	flowop_options_t *fo = (flowop_options_t *)options;

	if (fo != NULL) {
		timeout = (int) fo->poll_timeout/1.0e+6;
	}
	/* HACK: Force timeout for VSOCK DGRAM */
	/* if (timeout == 0) */
		/* timeout = VSOCK_TIMEOUT; */

	nleft = n;
	if (fo && FO_NONBLOCKING(fo)) {
		/*
		 * First try to read, if EWOULDBLOCK, then
		 * poll for fo->timeout seconds
		 */
		ret = read_one(pd->sock, buffer, n, &pd->addr_info);
		/* Lets fallback to poll/read */
		if ((ret <= 0) && (errno != EWOULDBLOCK)) {
			uperf_log_msg(UPERF_LOG_ERROR, errno,
			    "non-block write");
			return (ret);
		}
		nleft = n - ret;
	}
	if ((nleft > 0) && (timeout > 0)) {
		ret = generic_poll(pd->sock, timeout, POLLIN);
		if (ret > 0)
			return (read_one(pd->sock, buffer, nleft, &pd->addr_info));
		else
			return (-1); /* ret == 0 means timeout (error); */
	} else if ((nleft > 0) && (timeout <= 0)) {
		/* Vanilla read */
		return (read_one(pd->sock, buffer, nleft, &pd->addr_info));
	}
	assert(0); /* Not reached */

	return (UPERF_FAILURE);
}

/*
 * Function: protocol_vsock_dgram_write Description: vsock_dgram implementation of write We
 * cannot use send() as the server may not have done a connect()
 */
static int
protocol_vsock_dgram_write(protocol_t *p, void *buffer, int n, void *options)
{
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *) p->_protocol_p;
	int ret;
	size_t nleft;
	int timeout = 0;
	flowop_options_t *fo = (flowop_options_t *)options;

	if (fo != NULL) {
		timeout = (int) fo->poll_timeout/1.0e+6;
	}

	nleft = n;

	if (fo && FO_NONBLOCKING(fo)) {
		/*
		 * First try to write, if EWOULDBLOCK, then
		 * poll for fo->timeout seconds
		 */
		ret = write_one(pd->sock, buffer, n,
				(struct sockaddr *)&pd->addr_info);
		if ((ret <= 0) && (errno != EWOULDBLOCK)) {
			uperf_log_msg(UPERF_LOG_ERROR, errno,
			    "non-block write");
			return (-1);
		} else if (ret > 0) {
			nleft = n - ret;
		}
	}

	if ((nleft > 0) && (timeout > 0)) {
		ret = generic_poll(pd->sock, timeout, POLLOUT);
		if (ret > 0)
			return (write_one(pd->sock, buffer, nleft,
					(struct sockaddr *)&pd->addr_info));
		else
			return (-1);
	} else if ((nleft > 0) && (timeout <= 0)) {
		/* Vanilla write */
		return (write_one(pd->sock, buffer, nleft,
				(struct sockaddr *)&pd->addr_info));
	}
	assert(0);

	return (UPERF_FAILURE);
}

/*
 * Function: protocol_vsock_dgram_listen Description: In UDP, there is no need for a
 * special "listen". All you need to do is to open the socket, you are then
 * in business
 */
/* ARGSUSED1 */
static int
protocol_vsock_dgram_listen(protocol_t *p, void *options)
{
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *)p->_protocol_p;
	struct sockaddr_vm *svm;
	socklen_t len;
	char msg[128];

	if ((pd->sock = socket(AF_VSOCK, SOCK_DGRAM, 0)) < 0) {
		(void) snprintf(msg, 128, "%s: Cannot create socket", "vsock_dgram");
		uperf_log_msg(UPERF_LOG_ERROR, errno, msg);
		return (UPERF_FAILURE);
	}

	svm = (struct sockaddr_vm *)&pd->addr_info;
	memset(svm, 0, sizeof(struct sockaddr_vm));
	svm->svm_family = AF_VSOCK;
	svm->svm_port = p->port == ANY_PORT ? VMADDR_PORT_ANY : p->port;
	svm->svm_cid = VMADDR_CID_ANY;

	if (bind(pd->sock, (const struct sockaddr *)svm, sizeof(struct sockaddr_vm)) < 0) {
		uperf_log_msg(UPERF_LOG_ERROR, errno, "bind");
		return (UPERF_FAILURE);
	}

	if (p->port == ANY_PORT) {
		memset(svm, 0, sizeof(struct sockaddr_vm));
		len = (socklen_t)sizeof(struct sockaddr_vm);
		if ((getsockname(pd->sock, (struct sockaddr *)svm, &len)) < 0) {
			uperf_log_msg(UPERF_LOG_ERROR, errno, "getsockname");
			return (UPERF_FAILURE);
		}

		p->port = svm->svm_port;
	}

	uperf_debug("Listening on port %d\n", p->port);
	return (p->port);
}

static protocol_t *
protocol_vsock_dgram_accept(protocol_t *p, void *options)
{
	char msg[32];
	char hostname[NI_MAXHOST];
	int port;
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *)p->_protocol_p;
	flowop_options_t *fo = (flowop_options_t *)options;

	(void) bzero(msg, sizeof (msg));
	if ((protocol_vsock_dgram_read(p, msg, strlen(VSOCK_HANDSHAKE), fo) <=
		UPERF_SUCCESS)) {
		uperf_log_msg(UPERF_LOG_ERROR, errno,
		    "Error in VSOCK DGRAM Handshake");
		uperf_info("\nError in VSOCK DGRAM Handshake\n");
		return (NULL);
	}

	(void) set_vsock_dgram_options(pd->sock, (flowop_options_t *)options);
	if (strcmp(msg, VSOCK_HANDSHAKE) != 0)
		return (NULL);

	pd->refcount++;

	switch (pd->addr_info.ss_family) {
	case AF_VSOCK:
	{
		struct sockaddr_vm *svm;
		svm = (struct sockaddr_vm *)&pd->addr_info;
		snprintf(hostname, sizeof(hostname), "%u", svm->svm_cid);
		port = svm->svm_port;
		break;
	}
	default:
		return (NULL);
		break;
	}
	uperf_info("Handshake[%s] with %s:%d\n", msg, hostname, port);
	return (p);
}

static int
protocol_vsock_dgram_connect(protocol_t *p, void *options)
{
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *)p->_protocol_p;
	flowop_options_t *fo = (flowop_options_t *)options;
	socklen_t len; 
	const int off = 0;

	uperf_debug("%s: Connecting to %s:%u\n",
		    protocol_to_str(p->type), p->host, p->port);

	(void) memset(&pd->addr_info, 0, sizeof(struct sockaddr_storage));
	if (protocol_vsock_sockaddr(&pd->addr_info, &len, p->host, p->port, 0) < 0) {
		return (UPERF_FAILURE);
	}

	if ((pd->sock = socket(pd->addr_info.ss_family, SOCK_DGRAM, 0)) < 0) {
		ulog_err("%s: Cannot create socket", protocol_to_str(p->type));
		return (UPERF_FAILURE);
	}

	switch (pd->addr_info.ss_family) {
	case AF_VSOCK:
		((struct sockaddr_vm *)&pd->addr_info)->svm_port = p->port;
		break;
	default:
		uperf_debug("Unsupported protocol family: %d\n", pd->addr_info.ss_family);
		return (UPERF_FAILURE);
		break;
	}
	(void) set_vsock_dgram_options(pd->sock, fo);
	if ((protocol_vsock_dgram_write(p, VSOCK_HANDSHAKE, strlen(VSOCK_HANDSHAKE),
		    NULL)) <= 0) {
		uperf_log_msg(UPERF_LOG_ERROR, errno, "Error in UDP Handshake");
		uperf_info("\nError in UDP Handshake\n");
		return (UPERF_FAILURE);
	}
	return (UPERF_SUCCESS);
}

static int
protocol_vsock_dgram_disconnect(protocol_t *p)
{
	vsock_dgram_private_data *pd = (vsock_dgram_private_data *) p->_protocol_p;
	uperf_debug("vsock_dgram - disconnect done\n");

	pd->refcount--;

	return (UPERF_SUCCESS);
}

protocol_t *
protocol_vsock_dgram_create(char *host, int port)
{
	protocol_t *newp;
	vsock_dgram_private_data *new_vsock_dgram_p;

	if ((newp = calloc(1, sizeof(protocol_t))) == NULL) {
		perror("calloc");
		return (NULL);
	}
	if ((new_vsock_dgram_p = calloc(1, sizeof(vsock_dgram_private_data))) == NULL) {
		perror("calloc");
		return (NULL);
	}
	if (strlen(host) == 0) {
		/* VMADDR_CID_LOCAL(1) is used for local communication */
		snprintf(newp->host, MAXHOSTNAME, "%u", VMADDR_CID_LOCAL);
	} else {
		strlcpy(newp->host, host, MAXHOSTNAME);
	}
	newp->connect = protocol_vsock_dgram_connect;
	newp->disconnect = protocol_vsock_dgram_disconnect;
	newp->read = generic_read;
	newp->write = generic_write;
	newp->listen = protocol_vsock_dgram_listen;
	newp->accept = protocol_vsock_dgram_accept;
	newp->wait = generic_undefined;
	newp->type = PROTOCOL_VSOCK_DGRAM;
	newp->_protocol_p = new_vsock_dgram_p;
	new_vsock_dgram_p->refcount = 0;
	uperf_debug("vsock_dgram - Creating VSOCK DGRAM Protocol to %s:%d\n", host, port);
	return (newp);
}

void vsock_dgram_fini(protocol_t *p) { vsock_dgram_private_data *pd; static int
	called = 0; called++; if (!p) return; pd = (vsock_dgram_private_data *)
		p->_protocol_p; if (!pd) return;
	/*
	 * In VSOCK, we use the exact same technique as UDP. That is, we use
	 * only one socket to communicate. If the master does multiple
	 * connects(), they are converted to do VSOCK_HANDSHAKE on this socket.
	 * Lets assume that the user wants to do 10 connects followed by 10
	 * disconnects.  Here, the 10 connects translates to 10
	 * VSOCK_HANDSHAKEs.  When the user does a disconnect, the normal thing
	 * to do is to close the socket. However, in UDP it will cause the
	 * following close() to fail, as the socket is already closed.  We can
	 * use a refcount to track number of connects and close only when the
	 * refcount reaches 0.
	 */
	if (pd->refcount < -1) {
		if (pd->sock > 0)
			(void) close(pd->sock);
		free(pd);
		free(p);
	}
}
