/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 *
 * Implements support for ja4.hash keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-ja4s-hash.h"

#include "detect-engine-helper.h"

#include "util-ja4.h"
#include "util-mem.h"

#include "app-layer-ssl.h"

#ifdef HAVE_JA4
static int DetectJa4SHashSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
int Ja4SIsDisabled(const char *type);
static InspectionBuffer *Ja4SDetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

static int g_ja4s_hash_buffer_id = 0;
static int g_ja4s_hash_keyword_id = 0;
#endif

/**
 * \brief Registration function for keyword: ja4s.hash
 */
void DetectJa4SHashRegister(void)
{
#ifdef HAVE_JA4
    SCSigTableElmt *kw = (SCSigTableElmt *)SCCalloc(1, sizeof(SCSigTableElmt));
    kw->name = "ja4s.hash";
    kw->desc = "sticky buffer to match the JA4S hash buffer";
    kw->Setup = (int (*)(void *, void *, const char *))DetectJa4SHashSetup;
    kw->flags |= SIGMATCH_NOOPT;
    kw->flags |= SIGMATCH_INFO_STICKY_BUFFER;
    g_ja4s_hash_keyword_id = DetectHelperKeywordRegister(kw);
    SCFree(kw);

    DetectHelperBufferMpmRegister("ja4s.hash", "TLS JA4S hash", ALPROTO_TLS, 1, 0, GetData);
    DetectHelperBufferMpmRegister("ja4s.hash", "TLS JA4S hash", ALPROTO_QUIC, 1, 0, Ja4SDetectGetHash);

    g_ja4s_hash_buffer_id = DetectBufferTypeGetByName("ja4s.hash");
#endif /* HAVE_JA4 */
}

#ifdef HAVE_JA4
/**
 * \brief this function setup the ja4.hash modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectJa4SHashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_ja4s_hash_buffer_id) < 0)
        return -1;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS && s->alproto != ALPROTO_QUIC) {
        SCLogError("rule contains conflicting protocols.");
        return -1;
    }

    /* try to enable JA4 */
    SSLEnableJA4();

    /* check if JA4 enabling had an effect */
    if (!RunmodeIsUnittests() && !SSLJA4IsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, g_ja4s_hash_keyword_id)) {
            SCLogError("JA4 support is not enabled");
        }
        return -2;
    }
    s->init_data->init_flags |= SIG_FLAG_INIT_JA;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->server_connp.ja4 == NULL) {
            return NULL;
        }

        uint8_t data[JA4S_HEX_LEN];
        SCJA4SGetHash(ssl_state->server_connp.ja4, (uint8_t(*)[JA4S_HEX_LEN])data);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, 0);
        InspectionBufferCopy(buffer, data, JA4S_HEX_LEN);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *Ja4SDetectGetHash(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_quic_tx_get_ja4s(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, NULL, 0);
        InspectionBufferCopy(buffer, (uint8_t *)b, JA4S_HEX_LEN);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}
#endif
