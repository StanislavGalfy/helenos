/*
 * Copyright (c) 2011 Vojtech Horky
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

/** @addtogroup libusb
 * @{
 */
/** @file
 * General communication with host controller driver (implementation).
 */
#include <devman.h>
#include <async.h>
#include <dev_iface.h>
#include <usb_iface.h>
#include <usbhc_iface.h>
#include <usb/hc.h>
#include <usb/debug.h>
#include <errno.h>
#include <assert.h>

/** Initialize connection to USB host controller.
 *
 * @param connection Connection to be initialized.
 * @param device Device connecting to the host controller.
 * @return Error code.
 */
int usb_hc_connection_initialize_from_device(usb_hc_connection_t *connection,
    ddf_dev_t *device)
{
	assert(connection);

	if (device == NULL) {
		return EBADMEM;
	}

	devman_handle_t hc_handle;
	int rc = usb_hc_find(device->handle, &hc_handle);
	if (rc != EOK) {
		return rc;
	}

	rc = usb_hc_connection_initialize(connection, hc_handle);

	return rc;
}

/** Manually initialize connection to USB host controller.
 *
 * @param connection Connection to be initialized.
 * @param hc_handle Devman handle of the host controller.
 * @return Error code.
 */
int usb_hc_connection_initialize(usb_hc_connection_t *connection,
    devman_handle_t hc_handle)
{
	assert(connection);

	connection->hc_handle = hc_handle;
	connection->hc_phone = -1;

	return EOK;
}

/** Open connection to host controller.
 *
 * @param connection Connection to the host controller.
 * @return Error code.
 */
int usb_hc_connection_open(usb_hc_connection_t *connection)
{
	assert(connection);

	if (usb_hc_connection_is_opened(connection)) {
		return EBUSY;
	}

	int phone = devman_device_connect(connection->hc_handle, 0);
	if (phone < 0) {
		return phone;
	}

	connection->hc_phone = phone;

	return EOK;
}

/** Tells whether connection to host controller is opened.
 *
 * @param connection Connection to the host controller.
 * @return Whether connection is opened.
 */
bool usb_hc_connection_is_opened(const usb_hc_connection_t *connection)
{
	assert(connection);

	return (connection->hc_phone >= 0);
}

/** Close connection to the host controller.
 *
 * @param connection Connection to the host controller.
 * @return Error code.
 */
int usb_hc_connection_close(usb_hc_connection_t *connection)
{
	assert(connection);

	if (!usb_hc_connection_is_opened(connection)) {
		return ENOENT;
	}

	int rc = async_hangup(connection->hc_phone);
	if (rc != EOK) {
		return rc;
	}

	connection->hc_phone = -1;

	return EOK;
}

/** Get handle of USB device with given address.
 *
 * @param[in] connection Opened connection to host controller.
 * @param[in] address Address of device in question.
 * @param[out] handle Where to write the device handle.
 * @return Error code.
 */
int usb_hc_get_handle_by_address(usb_hc_connection_t *connection,
    usb_address_t address, devman_handle_t *handle)
{
	if (!usb_hc_connection_is_opened(connection)) {
		return ENOENT;
	}

	sysarg_t tmp;
	int rc = async_req_2_1(connection->hc_phone,
	    DEV_IFACE_ID(USBHC_DEV_IFACE),
	    IPC_M_USBHC_GET_HANDLE_BY_ADDRESS,
	    address, &tmp);
	if ((rc == EOK) && (handle != NULL)) {
		*handle = tmp;
	}

	return rc;
}

/** Tell USB address assigned to device with given handle.
 *
 * @param dev_handle Devman handle of the USB device in question.
 * @return USB address or negative error code.
 */
usb_address_t usb_hc_get_address_by_handle(devman_handle_t dev_handle)
{
	int parent_phone = devman_parent_device_connect(dev_handle,
	    IPC_FLAG_BLOCKING);
	if (parent_phone < 0) {
		return parent_phone;
	}

	sysarg_t address;

	int rc = async_req_2_1(parent_phone, DEV_IFACE_ID(USB_DEV_IFACE),
	    IPC_M_USB_GET_ADDRESS,
	    dev_handle, &address);

	if (rc != EOK) {
		return rc;
	}

	async_hangup(parent_phone);

	return (usb_address_t) address;
}


/** Get host controller handle by its class index.
 *
 * @param class_index Class index for the host controller.
 * @param hc_handle Where to store the HC handle
 *	(can be NULL for existence test only).
 * @return Error code.
 */
int usb_ddf_get_hc_handle_by_class(size_t class_index,
    devman_handle_t *hc_handle)
{
	char *class_index_str;
	devman_handle_t hc_handle_tmp;
	int rc;

	rc = asprintf(&class_index_str, "%zu", class_index);
	if (rc < 0) {
		return ENOMEM;
	}
	rc = devman_device_get_handle_by_class("usbhc", class_index_str,
	    &hc_handle_tmp, 0);
	free(class_index_str);
	if (rc != EOK) {
		return rc;
	}

	if (hc_handle != NULL) {
		*hc_handle = hc_handle_tmp;
	}

	return EOK;
}

/** Find host controller handle that is ancestor of given device.
 *
 * @param[in] device_handle Device devman handle.
 * @param[out] hc_handle Where to store handle of host controller
 *	controlling device with @p device_handle handle.
 * @return Error code.
 */
int usb_hc_find(devman_handle_t device_handle, devman_handle_t *hc_handle)
{
	int parent_phone = devman_parent_device_connect(device_handle,
	    IPC_FLAG_BLOCKING);
	if (parent_phone < 0) {
		return parent_phone;
	}

	devman_handle_t h;
	int rc = async_req_1_1(parent_phone, DEV_IFACE_ID(USB_DEV_IFACE),
	    IPC_M_USB_GET_HOST_CONTROLLER_HANDLE, &h);

	async_hangup(parent_phone);

	if (rc != EOK) {
		return rc;
	}

	if (hc_handle != NULL) {
		*hc_handle = h;
	}

	return EOK;
}

/**
 * @}
 */