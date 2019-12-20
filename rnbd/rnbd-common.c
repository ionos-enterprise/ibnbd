/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * InfiniBand Network Block Driver
 *
 * Copyright (c) 2014 - 2017 ProfitBricks GmbH. All rights reserved.
 * Authors: Fabian Holler <mail@fholler.de>
 *          Jack Wang <jinpu.wang@profitbricks.com>
 *          Kleber Souza <kleber.souza@profitbricks.com>
 *          Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Milind Dumbare <Milind.dumbare@gmail.com>
 *
 * Copyright (c) 2017 - 2018 ProfitBricks GmbH. All rights reserved.
 * Authors: Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Authors: Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 */

/* Copyright (c) 2019 1&1 IONOS SE. All rights reserved.
 * Authors: Jack Wang <jinpu.wang@cloud.ionos.com>
 *          Danil Kipnis <danil.kipnis@cloud.ionos.com>
 *          Guoqing Jiang <guoqing.jiang@cloud.ionos.com>
 *          Lutz Pogrell <lutz.pogrell@cloud.ionos.com>
 */
#include "rnbd-proto.h"

const char *rnbd_access_mode_str(enum rnbd_access_mode mode)
{
	switch (mode) {
	case RNBD_ACCESS_RO:
		return "ro";
	case RNBD_ACCESS_RW:
		return "rw";
	case RNBD_ACCESS_MIGRATION:
		return "migration";
	default:
		return "unknown";
	}
}
