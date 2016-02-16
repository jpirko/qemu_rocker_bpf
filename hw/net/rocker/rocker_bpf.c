/*
 * QEMU rocker switch emulation - BPF processing support
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

#include "qemu/osdep.h"
#include "net/eth.h"
#include "qemu/iov.h"
#include "qemu/timer.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_desc.h"
#include "rocker_bpf.h"
#include "rocker_bpf_runner.h"

typedef struct bpf_prog {
    uint64_t cookie;
    uint32_t in_pport;
    BPFRunner *runner;
    struct {
        int64_t install_time;
        int64_t refresh_time;
        uint64_t runs;
    } stats;
} BPFProg;

typedef struct bpf {
    World *world;
    BPFProg *progs[ROCKER_FP_PORTS_MAX];
} BPF;

static BPFProg *bpf_prog_find(BPF *bpf, uint64_t cookie)
{
    int i;

    for (i = 0; i < ROCKER_FP_PORTS_MAX; i++) {
        BPFProg *prog = bpf->progs[i];

	if (prog->cookie == cookie)
	    return prog;
    }
    return NULL;
}

static int bpf_prog_add(BPF *bpf, BPFProg *prog)
{
    bpf->progs[prog->in_pport] = prog;
    return ROCKER_OK;
}

static void bpf_prog_del(BPF *bpf, BPFProg *prog)
{
    bpf->progs[prog->in_pport] = NULL;
}

static BPFProg *bpf_prog_alloc(uint64_t cookie, uint32_t in_pport)
{
    BPFProg *prog;
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) / 1000;

    prog = g_malloc0(sizeof(BPFProg));
    prog->cookie = cookie;
    prog->in_pport = in_pport;
    prog->stats.install_time = now;
    prog->stats.refresh_time = now;

    return prog;
}

static ssize_t bpf_ig(World *world, uint32_t pport,
                      const struct iovec *iov, int iovcnt)
{
    BPF *bpf= world_private(world);
    BPFProg *prog = bpf->progs[pport];

    bpf_runner_run(prog->runner, iov, iovcnt);
////////////////////////////////////////////////////////////////////////////////////////////////////////
//  We have to take care of retval here. Assuming the bfp program type is
//  a tc action, this should handle returned values of TC_ACT_*.
//  We should decide if the packet should be posted to host by:
//      rx_produce(world, pport, iov, iovcnt);
//  According to returned value, we should also count statistics
//  including packet drops etc. as well.
////////////////////////////////////////////////////////////////////////////////////////////////////////

    prog->stats.runs++;
    return iov_size(iov, iovcnt);
}

static int bpf_cmd_prog_add_mod(BPF *bpf, BPFProg *prog,
                                RockerTlv **tlvs)
{
    return ROCKER_OK;
}

static int bpf_cmd_prog_add(BPF *bpf, uint64_t cookie,
                            RockerTlv **tlvs)
{
    BPFProg *prog = bpf_prog_find(bpf, cookie);
    uint32_t in_pport;
    int err = ROCKER_OK;

    if (prog) {
        return -ROCKER_EEXIST;
    }

    if (!tlvs[ROCKER_TLV_BPF_PROG_IN_PPORT] ||
	!tlvs[ROCKER_TLV_BPF_PROG_CHUNK]) {
        return -ROCKER_EINVAL;
    }

/*////////////////////////////////////////////////////////////////////////////////////////////////////////
 *  We probably need to pass program type as well and check it here.\
 *  I believe that it makes sense to only support tc action type.
 *//////////////////////////////////////////////////////////////////////////////////////////////////////*/

    in_pport = rocker_tlv_get_le32(tlvs[ROCKER_TLV_BPF_PROG_IN_PPORT]);
    prog = bpf_prog_alloc(in_pport, cookie);
    if (!prog) {
        return -ROCKER_ENOMEM;
    }

    prog->runner = bpf_runner_create(tlvs[ROCKER_TLV_BPF_PROG_CHUNK]);
    if (!prog->runner) {
        return -EINVAL;
    }

    err = bpf_cmd_prog_add_mod(bpf, prog, tlvs);
    if (err) {
        bpf_runner_destroy(prog->runner);
        g_free(prog);
        return err;
    }

    return bpf_prog_add(bpf, prog);
}

static int bpf_cmd_prog_mod(BPF *bpf, uint64_t cookie,
                            RockerTlv **tlvs)
{
    BPFProg *prog = bpf_prog_find(bpf, cookie);

    if (!prog) {
        return -ROCKER_ENOENT;
    }

    return bpf_cmd_prog_add_mod(bpf, prog, tlvs);
}

static int bpf_cmd_prog_del(BPF *bpf, uint64_t cookie)
{
    BPFProg *prog = bpf_prog_find(bpf, cookie);

    if (!prog) {
        return -ROCKER_ENOENT;
    }

    bpf_prog_del(bpf, prog);
    bpf_runner_destroy(prog->runner);
    g_free(prog);

    return ROCKER_OK;
}

static int bpf_cmd_prog_get_stats(BPF *bpf, uint64_t cookie,
                                  struct desc_info *info, char *buf)
{
    BPFProg *prog = bpf_prog_find(bpf, cookie);
    size_t tlv_size;
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) / 1000;
    int pos;

    if (!prog) {
        return -ROCKER_ENOENT;
    }

    tlv_size = rocker_tlv_total_size(sizeof(uint32_t)) +  /* duration */
               rocker_tlv_total_size(sizeof(uint64_t));  /* runs */

    if (tlv_size > desc_buf_size(info)) {
        return -ROCKER_EMSGSIZE;
    }

    pos = 0;
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_BPF_PROG_STAT_DURATION,
                        (int32_t)(now - prog->stats.install_time));
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_BPF_PROG_STAT_RUNS,
                        prog->stats.runs);

    return desc_set_buf(info, tlv_size);
}

static int bpf_cmd(World *world, struct desc_info *info,
                   char *buf, uint16_t cmd, RockerTlv *cmd_info_tlv)
{
    BPF *bpf = world_private(world);
    RockerTlv *tlvs[ROCKER_TLV_BPF_PROG_MAX + 1];
    uint64_t cookie;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_BPF_PROG_MAX, cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_BPF_PROG_COOKIE]) {
        return -ROCKER_EINVAL;
    }

    cookie = rocker_tlv_get_le64(tlvs[ROCKER_TLV_BPF_PROG_COOKIE]);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_BPF_PROG_ADD:
        return bpf_cmd_prog_add(bpf, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_BPF_PROG_MOD:
        return bpf_cmd_prog_mod(bpf, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_BPF_PROG_DEL:
        return bpf_cmd_prog_del(bpf, cookie);
    case ROCKER_TLV_CMD_TYPE_BPF_PROG_GET_STATS:
        return bpf_cmd_prog_get_stats(bpf, cookie, info, buf);
    }

    return -ROCKER_ENOTSUP;
}

static int bpf_init(World *world)
{
    BPF *bpf = world_private(world);

    bpf->world = world;
    return 0;
}

static void bpf_uninit(World *world)
{
}

static WorldOps bpf_ops = {
    .name = "bpf",
    .init = bpf_init,
    .uninit = bpf_uninit,
    .ig = bpf_ig,
    .cmd = bpf_cmd,
};

World *bpf_world_alloc(Rocker *r)
{
    return world_alloc(r, sizeof(BPF), ROCKER_WORLD_TYPE_BPF, &bpf_ops);
}
