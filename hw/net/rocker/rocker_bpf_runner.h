/*
 * QEMU rocker switch emulation - BPF runner
 *
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _ROCKER_BPF_RUNNER_H_
#define _ROCKER_BPF_RUNNER_

#include "rocker_hw.h"

struct bpf_insn {
	uint8_t	code;		/* opcode */
	uint8_t	dst_reg:4;	/* dest register */
	uint8_t	src_reg:4;	/* source register */
	int16_t	off;		/* signed offset */
	int32_t	imm;		/* signed immediate constant */
};

typedef struct bpf_runner {
	const struct bpf_insn *insts;
	uint32_t len;
} BPFRunner;

BPFRunner *bpf_runner_create(RockerTlv *tlv_chunk);
void bpf_runner_destroy(BPFRunner *runner);
unsigned int bpf_runner_run(BPFRunner *runner, const struct iovec *iov,
			    int iovcnt);

#endif /* _ROCKER_BPF_RUNNER_H_ */
