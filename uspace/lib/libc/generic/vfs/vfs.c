/*
 * Copyright (c) 2008 Jakub Jermar 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @addtogroup libc
 * @{
 */
/** @file
 */

#include <vfs/vfs.h>
#include <vfs/canonify.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/types.h>
#include <ipc/ipc.h>
#include <ipc/services.h>
#include <async.h>
#include <atomic.h>
#include <futex.h>
#include <errno.h>
#include <string.h>
#include <devmap.h>
#include <ipc/vfs.h>
#include <ipc/devmap.h>

static int vfs_phone = -1;
static futex_t vfs_phone_futex = FUTEX_INITIALIZER;
static futex_t cwd_futex = FUTEX_INITIALIZER;

DIR *cwd_dir = NULL;
char *cwd_path = NULL;
size_t cwd_size = 0;

char *absolutize(const char *path, size_t *retlen)
{
	char *ncwd_path;
	char *ncwd_path_nc;

	futex_down(&cwd_futex);
	size_t size = str_size(path);
	if (*path != '/') {
		if (!cwd_path) {
			futex_up(&cwd_futex);
			return NULL;
		}
		ncwd_path_nc = malloc(cwd_size + 1 + size + 1);
		if (!ncwd_path_nc) {
			futex_up(&cwd_futex);
			return NULL;
		}
		str_cpy(ncwd_path_nc, cwd_size + 1 + size + 1, cwd_path);
		ncwd_path_nc[cwd_size] = '/';
		ncwd_path_nc[cwd_size + 1] = '\0';
	} else {
		ncwd_path_nc = malloc(size + 1);
		if (!ncwd_path_nc) {
			futex_up(&cwd_futex);
			return NULL;
		}
		ncwd_path_nc[0] = '\0';
	}
	str_append(ncwd_path_nc, cwd_size + 1 + size + 1, path);
	ncwd_path = canonify(ncwd_path_nc, retlen);
	if (!ncwd_path) {
		futex_up(&cwd_futex);
		free(ncwd_path_nc);
		return NULL;
	}
	/*
	 * We need to clone ncwd_path because canonify() works in-place and thus
	 * the address in ncwd_path need not be the same as ncwd_path_nc, even
	 * though they both point into the same dynamically allocated buffer.
	 */
	ncwd_path = str_dup(ncwd_path);
	free(ncwd_path_nc);
	if (!ncwd_path) {
		futex_up(&cwd_futex);
		return NULL;
	}
	futex_up(&cwd_futex);
	return ncwd_path;
}

static void vfs_connect(void)
{
	while (vfs_phone < 0)
		vfs_phone = ipc_connect_me_to_blocking(PHONE_NS, SERVICE_VFS, 0, 0);
}

int mount(const char *fs_name, const char *mp, const char *dev,
    const char *opts, unsigned int flags)
{
	int res;
	ipcarg_t rc;
	aid_t req;
	dev_handle_t dev_handle;
	
	res = devmap_device_get_handle(dev, &dev_handle, flags);
	if (res != EOK)
		return res;
	
	size_t mpa_size;
	char *mpa = absolutize(mp, &mpa_size);
	if (!mpa)
		return ENOMEM;
	
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_2(vfs_phone, VFS_MOUNT, dev_handle, flags, NULL);
	rc = ipc_data_write_start(vfs_phone, (void *) mpa, mpa_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(mpa);
		return (int) rc;
	}
	
	rc = ipc_data_write_start(vfs_phone, (void *) opts, str_size(opts));
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(mpa);
		return (int) rc;
	}

	rc = ipc_data_write_start(vfs_phone, (void *) fs_name, str_size(fs_name));
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(mpa);
		return (int) rc;
	}

	/* Ask VFS whether it likes fs_name. */
	rc = async_req_0_0(vfs_phone, IPC_M_PING);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(mpa);
		return (int) rc;
	}
	
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	free(mpa);
	
	return (int) rc;
}

static int _open(const char *path, int lflag, int oflag, ...)
{
	ipcarg_t rc;
	ipc_call_t answer;
	aid_t req;
	
	size_t pa_size;
	char *pa = absolutize(path, &pa_size);
	if (!pa)
		return ENOMEM;
	
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_3(vfs_phone, VFS_OPEN, lflag, oflag, 0, &answer);
	rc = ipc_data_write_start(vfs_phone, pa, pa_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(pa);
		return (int) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	free(pa);
	
	if (rc != EOK)
	    return (int) rc;
	
	return (int) IPC_GET_ARG1(answer);
}

int open(const char *path, int oflag, ...)
{
	return _open(path, L_FILE, oflag);
}

int open_node(fs_node_t *node, int oflag)
{
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	ipc_call_t answer;
	aid_t req = async_send_4(vfs_phone, VFS_OPEN_NODE, node->fs_handle,
	    node->dev_handle, node->index, oflag, &answer);
	
	ipcarg_t rc;
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	
	if (rc != EOK)
	    return (int) rc;
	
	return (int) IPC_GET_ARG1(answer);
}

int close(int fildes)
{
	ipcarg_t rc;
	
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	rc = async_req_1_0(vfs_phone, VFS_CLOSE, fildes);
	
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	
	return (int)rc;
}

ssize_t read(int fildes, void *buf, size_t nbyte) 
{
	ipcarg_t rc;
	ipc_call_t answer;
	aid_t req;

	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_1(vfs_phone, VFS_READ, fildes, &answer);
	rc = ipc_data_read_start(vfs_phone, (void *)buf, nbyte);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		return (ssize_t) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	if (rc == EOK)
		return (ssize_t) IPC_GET_ARG1(answer);
	else
		return rc;
}

ssize_t write(int fildes, const void *buf, size_t nbyte) 
{
	ipcarg_t rc;
	ipc_call_t answer;
	aid_t req;

	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_1(vfs_phone, VFS_WRITE, fildes, &answer);
	rc = ipc_data_write_start(vfs_phone, (void *)buf, nbyte);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		return (ssize_t) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	if (rc == EOK)
		return (ssize_t) IPC_GET_ARG1(answer);
	else
		return -1;
}

int fd_phone(int fildes)
{
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	ipcarg_t device;
	ipcarg_t rc = async_req_1_1(vfs_phone, VFS_DEVICE, fildes, &device);
	
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	
	if (rc != EOK)
		return -1;
	
	return devmap_device_connect((dev_handle_t) device, 0);
}

void fd_node(int fildes, fs_node_t *node)
{
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	ipcarg_t fs_handle;
	ipcarg_t dev_handle;
	ipcarg_t index;
	ipcarg_t rc = async_req_1_3(vfs_phone, VFS_NODE, fildes, &fs_handle,
	    &dev_handle, &index);
	
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	
	if (rc == EOK) {
		node->fs_handle = (fs_handle_t) fs_handle;
		node->dev_handle = (dev_handle_t) dev_handle;
		node->index = (fs_index_t) index;
	} else {
		node->fs_handle = 0;
		node->dev_handle = 0;
		node->index = 0;
	}
}

int fsync(int fildes)
{
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	ipcarg_t rc = async_req_1_0(vfs_phone, VFS_SYNC, fildes);
	
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	
	return (int) rc;
}

off_t lseek(int fildes, off_t offset, int whence)
{
	ipcarg_t rc;

	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	ipcarg_t newoffs;
	rc = async_req_3_1(vfs_phone, VFS_SEEK, fildes, offset, whence,
	    &newoffs);

	async_serialize_end();
	futex_up(&vfs_phone_futex);

	if (rc != EOK)
		return (off_t) -1;
	
	return (off_t) newoffs;
}

int ftruncate(int fildes, off_t length)
{
	ipcarg_t rc;
	
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	rc = async_req_2_0(vfs_phone, VFS_TRUNCATE, fildes, length);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	return (int) rc;
}

DIR *opendir(const char *dirname)
{
	DIR *dirp = malloc(sizeof(DIR));
	if (!dirp)
		return NULL;
	dirp->fd = _open(dirname, L_DIRECTORY, 0);
	if (dirp->fd < 0) {
		free(dirp);
		return NULL;
	}
	return dirp;
}

struct dirent *readdir(DIR *dirp)
{
	ssize_t len = read(dirp->fd, &dirp->res.d_name[0], NAME_MAX + 1);
	if (len <= 0)
		return NULL;
	return &dirp->res;
}

void rewinddir(DIR *dirp)
{
	(void) lseek(dirp->fd, 0, SEEK_SET);
}

int closedir(DIR *dirp)
{
	(void) close(dirp->fd);
	free(dirp);
	return 0;
}

int mkdir(const char *path, mode_t mode)
{
	ipcarg_t rc;
	aid_t req;
	
	size_t pa_size;
	char *pa = absolutize(path, &pa_size);
	if (!pa)
		return ENOMEM;
	
	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_1(vfs_phone, VFS_MKDIR, mode, NULL);
	rc = ipc_data_write_start(vfs_phone, pa, pa_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(pa);
		return (int) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	free(pa);
	return rc;
}

static int _unlink(const char *path, int lflag)
{
	ipcarg_t rc;
	aid_t req;
	
	size_t pa_size;
	char *pa = absolutize(path, &pa_size);
	if (!pa)
		return ENOMEM;

	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_0(vfs_phone, VFS_UNLINK, NULL);
	rc = ipc_data_write_start(vfs_phone, pa, pa_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(pa);
		return (int) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	free(pa);
	return rc;
}

int unlink(const char *path)
{
	return _unlink(path, L_NONE);
}

int rmdir(const char *path)
{
	return _unlink(path, L_DIRECTORY);
}

int rename(const char *old, const char *new)
{
	ipcarg_t rc;
	aid_t req;
	
	size_t olda_size;
	char *olda = absolutize(old, &olda_size);
	if (!olda)
		return ENOMEM;

	size_t newa_size;
	char *newa = absolutize(new, &newa_size);
	if (!newa) {
		free(olda);
		return ENOMEM;
	}

	futex_down(&vfs_phone_futex);
	async_serialize_start();
	vfs_connect();
	
	req = async_send_0(vfs_phone, VFS_RENAME, NULL);
	rc = ipc_data_write_start(vfs_phone, olda, olda_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(olda);
		free(newa);
		return (int) rc;
	}
	rc = ipc_data_write_start(vfs_phone, newa, newa_size);
	if (rc != EOK) {
		async_wait_for(req, NULL);
		async_serialize_end();
		futex_up(&vfs_phone_futex);
		free(olda);
		free(newa);
		return (int) rc;
	}
	async_wait_for(req, &rc);
	async_serialize_end();
	futex_up(&vfs_phone_futex);
	free(olda);
	free(newa);
	return rc;
}

int chdir(const char *path)
{
	size_t pa_size;
	char *pa = absolutize(path, &pa_size);
	if (!pa)
		return ENOMEM;

	DIR *d = opendir(pa);
	if (!d) {
		free(pa);
		return ENOENT;
	}

	futex_down(&cwd_futex);
	if (cwd_dir) {
		closedir(cwd_dir);
		cwd_dir = NULL;
		free(cwd_path);	
		cwd_path = NULL;
		cwd_size = 0;
	}
	cwd_dir = d;
	cwd_path = pa;
	cwd_size = pa_size;
	futex_up(&cwd_futex);
	return EOK;
}

char *getcwd(char *buf, size_t size)
{
	if (!size)
		return NULL;
	futex_down(&cwd_futex);
	if (size < cwd_size + 1) {
		futex_up(&cwd_futex);
		return NULL;
	}
	str_cpy(buf, size, cwd_path);
	futex_up(&cwd_futex);
	return buf;
}

/** @}
 */
