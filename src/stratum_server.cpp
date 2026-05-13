/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "stratum_server.h"
#include "block_template.h"
#include "p2pool.h"
#include "side_chain.h"
#include "params.h"
#include "p2pool_api.h"
#include "p2p_server.h"

#include "rapidjson_wrapper.h"

LOG_CATEGORY(StratumServer)

static constexpr int DEFAULT_BACKLOG = 128;
static constexpr uint64_t MIN_DIFF = 1000;
static constexpr uint64_t AUTO_DIFF_TARGET_TIME = 30;

// Use short target format (4 bytes) for diff <= 4 million
static constexpr uint64_t TARGET_4_BYTES_LIMIT = std::numeric_limits<uint64_t>::max() / 4000001;

static constexpr uint64_t AUTODIFF_START = std::numeric_limits<uint64_t>::max() / 500001;

static constexpr int32_t BAD_SHARE_POINTS = -5;
static constexpr int32_t GOOD_SHARE_POINTS = 1;
static constexpr int32_t BAN_THRESHOLD_POINTS = -15;
static constexpr int32_t MAX_SCORE = 1000;

namespace p2pool {

StratumServer::StratumServer(p2pool* pool)
	: TCPServer(DEFAULT_BACKLOG, StratumClient::allocate, std::string(), Params::ProxyType::INVALID, pool->params().m_stratumProxyProtocol)
	, m_pool(pool)
	, m_autoDiff(pool->params().m_autoDiff)
	, m_enableFullValidation(pool->params().m_enableFullValidation)
	, m_rng(RandomDeviceSeed::instance)
	, m_cumulativeHashes(0)
	, m_cumulativeHashesAtLastShare(0)
	, m_hashrateDataHead(0)
	, m_hashrateDataTail_15m(0)
	, m_hashrateDataTail_1h(0)
	, m_hashrateDataTail_24h(0)
	, m_cumulativeFoundSharesDiff(0.0)
	, m_totalFoundSidechainShares(0)
	, m_totalFailedSidechainShares(0)
	, m_lastSidechainShareFoundTime(0)
	, m_totalStratumShares(0)
	, m_apiLastUpdateTime(0)
{
	// Need a bigger buffer for the TLS handshake
	m_callbackBuf.resize(STRATUM_CALLBACK_BUF_SIZE);

	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	m_hashrateData[0] = { seconds_since_epoch(), 0 };

	uv_mutex_init_checked(&m_resetShareCountersLock);
	uv_mutex_init_checked(&m_blobsQueueLock);
	uv_mutex_init_checked(&m_showWorkersLock);
	uv_mutex_init_checked(&m_rngLock);
	uv_rwlock_init_checked(&m_hashrateDataLock);
	uv_rwlock_init_checked(&m_walletTemplatesLock);
	uv_rwlock_init_checked(&m_walletStatsLock);

	m_extraNonce = get_random32();

	uv_async_init_checked(&m_loop, &m_resetShareCountersAsync, on_reset_share_counters);
	m_resetShareCountersAsync.data = this;

	uv_async_init_checked(&m_loop, &m_blobsAsync, on_blobs_ready);
	m_blobsAsync.data = this;
	m_blobsQueue.reserve(2);

	uv_async_init_checked(&m_loop, &m_showWorkersAsync, on_show_workers);
	m_showWorkersAsync.data = this;

	const Params& params = pool->params();
	m_banTime = params.m_stratumBanTime;
	start_listening(params.m_stratumAddresses, params.m_upnp && params.m_upnpStratum);
}

StratumServer::~StratumServer()
{
	shutdown_tcp();

	{
		MutexLock lock(m_blobsQueueLock);

		for (BlobsData* data : m_blobsQueue) {
			delete data;
		}
	}

	{
		WriteLock lock(m_walletTemplatesLock);
		for (auto& kv : m_walletTemplates) {
			delete kv.second.tpl;
			kv.second.tpl = nullptr;
		}
		m_walletTemplates.clear();
	}

	uv_mutex_destroy(&m_resetShareCountersLock);
	uv_mutex_destroy(&m_blobsQueueLock);
	uv_mutex_destroy(&m_showWorkersLock);
	uv_mutex_destroy(&m_rngLock);
	uv_rwlock_destroy(&m_hashrateDataLock);
	uv_rwlock_destroy(&m_walletTemplatesLock);
	uv_rwlock_destroy(&m_walletStatsLock);
}

BlockTemplate* StratumServer::template_for(const Wallet& w) const
{
	if (!w.valid()) {
		return nullptr;
	}
	ReadLock lock(m_walletTemplatesLock);
	auto it = m_walletTemplates.find(wallet_key(w));
	if (it == m_walletTemplates.end()) {
		return nullptr;
	}
	return it->second.tpl;
}

BlockTemplate* StratumServer::acquire_template_for(const Wallet& w)
{
	if (!w.valid()) {
		return nullptr;
	}

	const WalletKey key = wallet_key(w);

	{
		WriteLock lock(m_walletTemplatesLock);

		auto it = m_walletTemplates.find(key);
		if (it != m_walletTemplates.end()) {
			++it->second.ref_count;
			return it->second.tpl;
		}

		if (m_walletTemplates.size() >= MAX_UNIQUE_MINER_WALLETS) {
			LOGWARN(1, "per-miner wallet template cache full (" << m_walletTemplates.size() << " entries), miner falls back to pool-operator wallet");
			return nullptr;
		}

		// Build a BlockTemplate bound to this miner wallet. Its coinbase tip output
		// will pay to w instead of params.m_miningWallet.
		BlockTemplate* tpl = new BlockTemplate(&m_pool->side_chain(), m_pool->hasher(), w);

		WalletTemplateEntry entry;
		entry.tpl = tpl;
		entry.ref_count = 1;
		m_walletTemplates.emplace(key, entry);
	}

	// Prime the new template with current MinerData/Mempool/Params so it can
	// serve hashing blobs immediately (done without holding m_walletTemplatesLock
	// since update() acquires BlockTemplate's own rwlock).
	BlockTemplate* tpl = template_for(w);
	if (tpl) {
		tpl->update(m_pool->miner_data(), m_pool->mempool(), m_pool->params());
	}
	return tpl;
}

void StratumServer::release_template_for(const Wallet& w)
{
	if (!w.valid()) {
		return;
	}
	WriteLock lock(m_walletTemplatesLock);
	auto it = m_walletTemplates.find(wallet_key(w));
	if (it == m_walletTemplates.end()) {
		return;
	}
	if (it->second.ref_count > 0) {
		--it->second.ref_count;
	}
	// v1: do not evict entries even when ref_count hits 0. Simplifies lifetime
	// for in-flight submits and avoids the async/worker race of deletion.
}

bool StratumServer::is_our_wallet(const Wallet& w) const
{
	if (!w.valid()) {
		return false;
	}
	if (w == m_pool->params().m_miningWallet) {
		return true;
	}
	ReadLock lock(m_walletTemplatesLock);
	return m_walletTemplates.find(wallet_key(w)) != m_walletTemplates.end();
}

void StratumServer::format_wallet(const Wallet& w, char (&buf)[Wallet::ADDRESS_LENGTH + 1]) const
{
	if (!w.valid()) {
		buf[0] = '\0';
		return;
	}
	// Wallet::encode writes exactly ADDRESS_LENGTH chars with no terminator —
	// we NUL-terminate so the buffer is usable with the log streams below.
	char full[Wallet::ADDRESS_LENGTH];
	w.encode(full);
	memcpy(buf, full, Wallet::ADDRESS_LENGTH);
	buf[Wallet::ADDRESS_LENGTH] = '\0';
}

void StratumServer::on_block(const BlockTemplate& block)
{
	LOGINFO(4, "new block template at height " << block.height());

	const uint32_t num_connections = m_numConnections;
	if (num_connections == 0) {
		LOGINFO(4, "no clients connected");
		update_hashrate_data(0, seconds_since_epoch());
		api_update_local_stats(seconds_since_epoch());
		return;
	}

	// Update all per-wallet templates with the same MinerData so they share
	// aux_nonce (critical for merge mining consistency).
	{
		const MinerData data = m_pool->miner_data();
		const Mempool& mempool = m_pool->mempool();
		const Params& params = m_pool->params();

		ReadLock lock(m_walletTemplatesLock);
		for (auto& kv : m_walletTemplates) {
			if (kv.second.tpl) {
				kv.second.tpl->update(data, mempool, params);
			}
		}
	}

	const uint32_t extra_nonce_start = get_random32();
	m_extraNonce.exchange(extra_nonce_start + num_connections);

	BlobsData* blobs_data = new BlobsData{};
	blobs_data->m_extraNonceStart = extra_nonce_start;

	difficulty_type difficulty;
	difficulty_type aux_diff;
	difficulty_type sidechain_difficulty;
	size_t nonce_offset;

	// More clients might connect between now and when we actually go through clients list - get_hashing_blobs() and async send take some time
	// Even if they do, they'll be added to the beginning of the list and will get their block template in on_login()
	// We'll iterate through the list backwards so when we get to the beginning and run out of extra_nonce values, it'll be only new clients left
	blobs_data->m_numClientsExpected = num_connections;
	blobs_data->m_blobSize = block.get_hashing_blobs(extra_nonce_start, num_connections, blobs_data->m_blobs, blobs_data->m_height, difficulty, aux_diff, sidechain_difficulty, blobs_data->m_seedHash, nonce_offset, blobs_data->m_templateId);

	// Integrity checks
	if (blobs_data->m_blobSize < 76) {
		LOGERR(1, "internal error: get_hashing_blobs returned too small blobs (" << blobs_data->m_blobSize << " bytes)");
		delete blobs_data;
		return;
	}

	if (blobs_data->m_blobs.size() != blobs_data->m_blobSize * num_connections) {
		LOGERR(1, "internal error: get_hashing_blobs returned wrong amount of data");
		delete blobs_data;
		return;
	}

	if (pool_block_debug() && (num_connections > 1)) {
		std::vector<uint64_t> blob_hashes;
		blob_hashes.reserve(num_connections);

		const uint8_t* data = blobs_data->m_blobs.data();
		const size_t size = blobs_data->m_blobSize;

		// Get first 8 bytes of the Merkle root hash from each blob
		for (size_t i = 0; i < num_connections; ++i) {
			blob_hashes.emplace_back(read_unaligned(reinterpret_cast<const uint64_t*>(data + i * size + 43)));
		}

		// Find duplicates
		std::sort(blob_hashes.begin(), blob_hashes.end());

		for (uint32_t i = 1; i < num_connections; ++i) {
			if (blob_hashes[i - 1] == blob_hashes[i]) {
				LOGERR(1, "internal error: get_hashing_blobs returned two identical blobs");
				delete blobs_data;
				return;
			}
		}
	}

	blobs_data->m_target = std::max(difficulty.target(), sidechain_difficulty.target());
	blobs_data->m_target = std::max(blobs_data->m_target, aux_diff.target());

	{
		MutexLock lock(m_blobsQueueLock);

		if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_blobsAsync))) {
			delete blobs_data;
			return;
		}

		m_blobsQueue.push_back(blobs_data);

		const int err = uv_async_send(&m_blobsAsync);
		if (err) {
			LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));

			m_blobsQueue.pop_back();
			delete blobs_data;
		}
	}

	update_hashrate_data(0, seconds_since_epoch());
	api_update_local_stats(seconds_since_epoch());
}

template<size_t N>
static bool get_custom_user(const char* s, char (&user)[N])
{
	size_t len = 0;

	// Find first of '+' or '.', drop non-printable characters
	while (s && (len < N - 1)) {
		const char c = *s;
		if (!c) {
			break;
		}
		if ((c == '+') || (c == '.')) {
			break;
		}
		// Limit to printable ASCII characters, also skip comma and JSON special characters
		if (c >= ' ' && c <= '~' && c != ',' && c != '"' && c != '\\') {
			user[len++] = c;
		}
		++s;
	}
	user[len] = '\0';

	return (len > 0);
}

// Extract the raw login prefix (before '+' or '.') without the 32-char cap
// of m_customUser — Monero addresses are 95 chars. No character filtering
// since base58 is a strict subset of printable ASCII.
static void get_login_prefix(const char* s, char (&buf)[Wallet::ADDRESS_LENGTH + 1])
{
	size_t len = 0;
	while (s && (len < Wallet::ADDRESS_LENGTH)) {
		const char c = *s;
		if (!c || c == '+' || c == '.') {
			break;
		}
		buf[len++] = c;
		++s;
	}
	buf[len] = '\0';
}

static bool get_custom_diff(const char* s, difficulty_type& diff)
{
	const char* diff_str = nullptr;

	// Find last of '+' or '.'
	while (s) {
		const char c = *s;
		if (!c) {
			break;
		}
		if ((c == '+') || (c == '.')) {
			diff_str = s;
		}
		++s;
	}

	if (diff_str) {
		const uint64_t t = strtoull(diff_str + 1, nullptr, 10);
		if (t) {
			// Don't let clients set difficulty less than MIN_DIFF
			diff = { std::max<uint64_t>(t + 1, MIN_DIFF), 0 };
			return true;
		}
	}

	return false;
}

bool StratumServer::on_login(StratumClient* client, uint32_t id, const char* login)
{
	const P2PServer* p2p_server = m_pool->p2p_server();

	// If there are no connections to other P2Pool peers, don't let Stratum clients connect
	if (p2p_server && p2p_server->disconnected()) {
		const bool result = send(client, [id](uint8_t* buf, size_t buf_size) {
			log::Stream s(buf, buf_size);
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Disconnected from P2Pool network\"}}\n";
			return s.m_pos;
		});

		if (!result) {
			return false;
		}

		client->close();
		return true;
	}

	if (client->m_rpcId) {
		LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " tried to login, but it's already logged in");
		return false;
	}

	// Parse the wallet from the raw login prefix. If it decodes and matches the
	// pool-operator's network type, use it. Otherwise fall back to the operator
	// wallet so old xmrig configs (or invalid addresses) still mine via the
	// operator's coinbase output.
	{
		char addr_buf[Wallet::ADDRESS_LENGTH + 1] = {};
		get_login_prefix(login, addr_buf);

		Wallet w(nullptr);
		const Wallet& fallback = m_pool->params().m_miningWallet;
		if (w.decode(addr_buf) && w.valid() && (w.type() == fallback.type())) {
			client->m_minerWallet = w;
		}
		else {
			client->m_minerWallet = fallback;
		}
	}

	// Get (or create) the per-miner BlockTemplate for this wallet.
	// nullptr means cache is full -> fall back to the operator wallet's template.
	BlockTemplate* tpl = acquire_template_for(client->m_minerWallet);
	if (!tpl) {
		client->m_minerWallet = m_pool->params().m_miningWallet;
		tpl = &m_pool->block_template();
	}

	const uint32_t extra_nonce = m_extraNonce.fetch_add(1);

	uint8_t hashing_blob[128];
	uint64_t height, sidechain_height;
	difficulty_type difficulty;
	difficulty_type aux_diff;
	difficulty_type sidechain_difficulty;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;

	const size_t blob_size = tpl->get_hashing_blob(extra_nonce, hashing_blob, height, sidechain_height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset, template_id);

	uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());
	target = std::max(target, aux_diff.target());

	if (get_custom_diff(login, client->m_customDiff)) {
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " set custom difficulty " << client->m_customDiff);
		target = std::max(target, client->m_customDiff.target());
	}
	else if (m_autoDiff) {
		// Limit autodiff to 4000000 for maximum compatibility
		target = std::max(target, std::max(AUTODIFF_START, TARGET_4_BYTES_LIMIT));
	}

	if (get_custom_user(login, client->m_customUser)) {
		const char* s = client->m_customUser;
		LOGINFO(5, "client " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " set custom user " << s);
	}

	{
		// Default log level (3) so the operator can see which wallet each miner
		// bound to — this is the single source of truth for "where do this
		// miner's shares go?". Logging at 0 would be too chatty on reconnect storms.
		char wallet_buf[Wallet::ADDRESS_LENGTH + 1];
		format_wallet(client->m_minerWallet, wallet_buf);
		LOGINFO(3, log::LightCyan() << "client " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor()
			<< " logged in with wallet " << log::Green() << static_cast<const char*>(wallet_buf));
	}

	uint32_t job_id;
	{
		job_id = ++client->m_perConnectionJobId;

		StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
		saved_job.job_id = job_id;
		saved_job.extra_nonce = extra_nonce;
		saved_job.template_id = template_id;
		saved_job.target = target;
	}
	client->m_lastJobTarget = target;

	uint32_t rpc_id;
	do {
		rpc_id = static_cast<StratumServer*>(client->m_owner)->get_random32();
	} while (!rpc_id);

	const bool result = send(client,
		[rpc_id, id, &hashing_blob, job_id, blob_size, target, height, &seed_hash](uint8_t* buf, size_t buf_size)
		{
			log::hex_buf target_hex(&target);

			if (target >= TARGET_4_BYTES_LIMIT) {
				target_hex.m_data += sizeof(uint32_t);
				target_hex.m_size -= sizeof(uint32_t);
			}

			log::Stream s(buf, buf_size);
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{\"id\":\"";
			s << log::Hex(rpc_id) << "\",\"job\":{\"blob\":\"";
			s << log::hex_buf(hashing_blob, blob_size) << "\",\"job_id\":\"";
			s << log::Hex(job_id) << "\",\"target\":\"";
			s << target_hex << "\",\"algo\":\"rx/0\",\"height\":";
			s << height << ",\"seed_hash\":\"";
			s << seed_hash << "\"},\"extensions\":[\"algo\"],\"status\":\"OK\"}}\n";
			return s.m_pos;
		});

	if (result) {
		client->m_rpcId = rpc_id;
	}

	return result;
}

bool StratumServer::on_submit(StratumClient* client, uint32_t id, const char* job_id_str, const char* nonce_str, const char* result_str)
{
	uint32_t job_id = 0;

	for (size_t i = 0; job_id_str[i]; ++i) {
		uint32_t d;
		if (!from_hex(job_id_str[i], d)) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('job_id' is not a hex integer)");
			return false;
		}
		job_id = (job_id << 4) + d;
	}

	if (!job_id) {
		LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('job_id' can't be 0)");
		return false;
	}

	uint32_t nonce = 0;

	for (int i = static_cast<int>(sizeof(uint32_t)) - 1; i >= 0; --i) {
		uint32_t d[2];
		if (!from_hex(nonce_str[i * 2 + 0], d[0]) || !from_hex(nonce_str[i * 2 + 1], d[1])) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('nonce' is not a hex integer)");
			return false;
		}
		nonce = (nonce << 8) | (d[0] << 4) | d[1];
	}

	hash resultHash;

	for (size_t i = 0; i < HASH_SIZE; ++i) {
		uint32_t d[2];
		if (!from_hex(result_str[i * 2 + 0], d[0]) || !from_hex(result_str[i * 2 + 1], d[1])) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " invalid params ('result' is not a hex value)");
			return false;
		}
		resultHash.h[i] = static_cast<uint8_t>((d[0] << 4) | d[1]);
	}

	uint32_t template_id = 0;
	uint32_t extra_nonce = 0;
	uint64_t target = 0;

	bool found = false;
	{
		const StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
		if (saved_job.job_id == job_id) {
			template_id = saved_job.template_id;
			extra_nonce = saved_job.extra_nonce;
			target = saved_job.target;
			found = true;
		}
	}

	if (found) {
		// Route to the per-wallet BlockTemplate for this client
		BlockTemplate* tpl = template_for(client->m_minerWallet);
		if (!tpl) {
			tpl = &m_pool->block_template();
		}
		const BlockTemplate& block = *tpl;
		uint64_t height, sidechain_height;
		difficulty_type mainchain_diff, aux_diff, sidechain_diff;

		if (!block.get_difficulties(template_id, height, sidechain_height, mainchain_diff, aux_diff, sidechain_diff)) {
			LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a stale share");
			return send(client,
				[id](uint8_t* buf, size_t buf_size)
				{
					log::Stream s(buf, buf_size);
					s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n";
					return s.m_pos;
				});
		}

		if (mainchain_diff.check_pow(resultHash)) {
			const char* s = client->m_customUser;
			char w[Wallet::ADDRESS_LENGTH + 1];
			format_wallet(client->m_minerWallet, w);
			LOGINFO(0, log::Green() << "client " << static_cast<char*>(client->m_addrString) << (*s ? " user " : "") << s << " wallet " << static_cast<const char*>(w) << " found a mainchain block at height " << height << ", submitting it");
			// Pass tpl so submit_block() resolves template_id against the per-miner-wallet
			// template — using the main template here would miss (template_id not found).
			m_pool->submit_block_async(template_id, nonce, extra_nonce, tpl);
		}

		if (aux_diff.check_pow(resultHash)) {
			const std::vector<AuxChainData> aux_chains = block.get_aux_chains(template_id);

			std::vector<p2pool::SubmitAuxBlockData> aux_blocks;
			aux_blocks.reserve(aux_chains.size());

			for (const AuxChainData& aux_data : aux_chains) {
				if (aux_data.difficulty.check_pow(resultHash)) {
					const char* s = client->m_customUser;
					char w[Wallet::ADDRESS_LENGTH + 1];
					format_wallet(client->m_minerWallet, w);
					LOGINFO(0, log::Green() << "client " << static_cast<char*>(client->m_addrString) << (*s ? " user " : "") << s << " wallet " << static_cast<const char*>(w) << " found an aux block for chain_id " << aux_data.unique_id << ", diff " << aux_data.difficulty << ", submitting it");
					// Same per-wallet-template plumbing for aux submits so the merge-mining
					// merkle proof matches the coinbase the miner actually hashed.
					aux_blocks.emplace_back(p2pool::SubmitAuxBlockData{ aux_data.unique_id, template_id, nonce, extra_nonce, tpl });
				}
			}

			if (!aux_blocks.empty()) {
				m_pool->submit_aux_block_async(aux_blocks);
			}
		}

		if (target >= TARGET_4_BYTES_LIMIT) {
			// "Low diff share" fix: adjust target to the same value as XMRig would use
			target = std::numeric_limits<uint64_t>::max() / (std::numeric_limits<uint32_t>::max() / (target >> 32));
		}

		SubmittedShare share{};

		share.m_req.data = &share;
		share.m_allocated = false;

		share.m_server = this;
		share.m_client = client;
		share.m_tpl = tpl;
		share.m_clientIPv6 = client->isV6();
		share.m_clientAddr = client->m_addr;
		memcpy(share.m_clientAddrString, client->m_addrString, sizeof(share.m_clientAddrString));
		memcpy(share.m_clientCustomUser, client->m_customUser, sizeof(share.m_clientCustomUser));
		format_wallet(client->m_minerWallet, share.m_clientWallet);
		share.m_clientResetCounter = client->m_resetCounter.load();
		share.m_rpcId = client->m_rpcId;
		share.m_id = id;
		share.m_templateId = template_id;
		share.m_nonce = nonce;
		share.m_extraNonce = extra_nonce;
		share.m_target = target;
		share.m_resultHash = resultHash;
		share.m_sidechainDifficulty = sidechain_diff;
		share.m_mainchainHeight = height;
		share.m_sidechainHeight = sidechain_height;
		share.m_effort = -1.0;
		share.m_timestamp = seconds_since_epoch();
		share.m_isMainchainBlock = mainchain_diff.check_pow(resultHash);

		uint64_t rem;
		share.m_hashes = (target > 1) ? udiv128(1, 0, target, &rem) : 1;
		share.m_highEnoughDifficulty = sidechain_diff.check_pow(resultHash);
		share.m_score = 0;

		// Don't count shares that were found during sync
		const SideChain& side_chain = m_pool->side_chain();
		const PoolBlock* tip = side_chain.chainTip();
		if (tip && (sidechain_height + side_chain.chain_window_size() < tip->m_sidechainHeight)) {
			share.m_highEnoughDifficulty = false;
		}

		update_auto_diff(client, share.m_timestamp, share.m_hashes);

		++client->m_stratumShares;

		// If this share is below sidechain difficulty, process it in this thread because it'll be quick
		if (!share.m_highEnoughDifficulty && !m_enableFullValidation) {
			on_share_found(&share.m_req);
			on_after_share_found(&share.m_req, 0);
			return true;
		}

		// Else switch to a worker thread to check PoW which can take a long time
		SubmittedShare* share2 = new SubmittedShare(share);

		share2->m_req.data = share2;
		share2->m_allocated = true;

		m_pendingShareChecks.push_back(share2);
		LOGINFO(5, "on_submit: pending share checks count = " << m_pendingShareChecks.size());

		// If there were no pending share checks, run on_share_found in background
		// on_after_share_found will pick the remaining share checks
		if (m_pendingShareChecks.size() == 1) {
			const int err = uv_queue_work(&m_loop, &share2->m_req, on_share_found, on_after_share_found);
			if (err) {
				LOGERR(1, "uv_queue_work failed, error " << uv_err_name(err));

				// If uv_queue_work failed, process this share here anyway
				on_share_found(&share2->m_req);
				on_after_share_found(&share2->m_req, 0);
			}
		}

		return true;
	}

	LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " got a share with invalid job id " << job_id << " (latest job sent has id " << client->m_perConnectionJobId << ')');

	const bool result = send(client,
		[id](uint8_t* buf, size_t buf_size)
		{
			log::Stream s(buf, buf_size);
			s << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid job id\"}}\n";
			return s.m_pos;
		});

	return result;
}

uint32_t StratumServer::get_random32()
{
	MutexLock lock(m_rngLock);
	return static_cast<uint32_t>(m_rng() >> 32);
}

void StratumServer::print_status()
{
	update_hashrate_data(0, seconds_since_epoch());
	print_stratum_status();
}

void StratumServer::show_workers_async()
{
	MutexLock lock(m_showWorkersLock);

	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_showWorkersAsync))) {
		uv_async_send(&m_showWorkersAsync);
	}
}

void StratumServer::show_workers()
{
	check_event_loop_thread(__func__);

	const uint64_t cur_time = seconds_since_epoch();
	const difficulty_type pool_diff = m_pool->side_chain().difficulty();

	int addr_len = 0;
	for (const StratumClient* c = static_cast<StratumClient*>(m_connectedClientsList->m_next); c != m_connectedClientsList; c = static_cast<StratumClient*>(c->m_next)) {
		addr_len = std::max(addr_len, static_cast<int>(strlen(c->m_addrString)));
	}

	size_t n = 0;

	// Full 95-char Monero address is displayed so the operator can copy/paste it
	// straight into a block explorer. Pad to ADDRESS_LENGTH + 2 for a separator.
	constexpr size_t WALLET_COL_W = Wallet::ADDRESS_LENGTH + 2;

	LOGINFO(0, log::pad_right("IP:port", addr_len + 8)
			<< "TLS    "
			<< log::pad_right("uptime", 20)
			<< log::pad_right("difficulty", 20)
			<< log::pad_right("hashrate", 15)
			<< log::pad_right("shares", 12)
			<< log::pad_right("wallet", WALLET_COL_W)
			<< "name"
	);

	for (const StratumClient* c = static_cast<StratumClient*>(m_connectedClientsList->m_next); c != m_connectedClientsList; c = static_cast<StratumClient*>(c->m_next)) {
		difficulty_type diff = pool_diff;
		if (c->m_lastJobTarget > 1) {
			uint64_t r;
			diff.lo = udiv128(1, 0, c->m_lastJobTarget, &r);
			diff.hi = 0;
			if (r) {
				++diff.lo;
			}
		}

#ifdef WITH_TLS
		const bool is_tls = !c->m_tls.is_empty();
#else
		constexpr bool is_tls = false;
#endif

		char shares_buf[16] = {};
		log::Stream s(shares_buf);
		s << c->m_sidechainShares << '/' << c->m_stratumShares << '\0';

		char wallet_buf[Wallet::ADDRESS_LENGTH + 1] = {};
		format_wallet(c->m_minerWallet, wallet_buf);

		LOGINFO(0, log::pad_right(static_cast<const char*>(c->m_addrString), addr_len + 8)
				<< (is_tls ? "yes    " : "no     ")
				<< log::pad_right(log::Duration(cur_time - c->m_connectedTime), 20)
				<< log::pad_right(diff, 20)
				<< log::pad_right(log::Hashrate(c->m_autoDiff.lo / AUTO_DIFF_TARGET_TIME, m_autoDiff && (c->m_autoDiff != 0)), 15)
				<< log::pad_right(static_cast<const char*>(shares_buf), 12)
				<< log::pad_right(*wallet_buf ? static_cast<const char*>(wallet_buf) : "-", WALLET_COL_W)
				<< (c->m_rpcId ? c->m_customUser : "not logged in")
		);
		++n;
	}

	LOGINFO(0, "Total: " << n << " workers");
}

void StratumServer::reset_share_counters()
{
	MutexLock lock(m_resetShareCountersLock);

	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_resetShareCountersAsync))) {
		uv_async_send(&m_resetShareCountersAsync);
	}
}

void StratumServer::on_reset_share_counters()
{
	check_event_loop_thread(__func__);

	for (StratumClient* c = static_cast<StratumClient*>(m_connectedClientsList->m_next); c != m_connectedClientsList; c = static_cast<StratumClient*>(c->m_next)) {
		c->m_stratumShares = 0;
		c->m_sidechainShares = 0;
	}

	WriteLock lock(m_hashrateDataLock);

	m_cumulativeHashesAtLastShare = m_cumulativeHashes;
	m_totalFoundSidechainShares = 0;
	m_totalFailedSidechainShares = 0;
	m_lastSidechainShareFoundTime = 0;
}

bool StratumServer::http_enabled() const
{
	return m_pool->params().m_enableStratumHTTP;
}

const char* StratumServer::get_log_category() const
{
	return log_category_prefix;
}

void StratumServer::print_stratum_status() const
{
	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;
	double average_effort;
	uint32_t sidechain_shares_found, sidechain_shares_failed;
	uint64_t total_stratum_shares;

	{
		ReadLock lock(m_hashrateDataLock);

		total_hashes = m_cumulativeHashes;
		hashes_since_last_share = m_cumulativeHashes - m_cumulativeHashesAtLastShare;

		const HashrateData* data = m_hashrateData;
		const HashrateData& head = data[m_hashrateDataHead];
		const HashrateData& tail_15m = data[m_hashrateDataTail_15m];
		const HashrateData& tail_1h = data[m_hashrateDataTail_1h];
		const HashrateData& tail_24h = data[m_hashrateDataTail_24h];

		hashes_15m = head.m_cumulativeHashes - tail_15m.m_cumulativeHashes;
		dt_15m = static_cast<int64_t>(head.m_timestamp - tail_15m.m_timestamp);

		hashes_1h = head.m_cumulativeHashes - tail_1h.m_cumulativeHashes;
		dt_1h = static_cast<int64_t>(head.m_timestamp - tail_1h.m_timestamp);

		hashes_24h = head.m_cumulativeHashes - tail_24h.m_cumulativeHashes;
		dt_24h = static_cast<int64_t>(head.m_timestamp - tail_24h.m_timestamp);

		average_effort = 0.0;
		const double diff = m_cumulativeFoundSharesDiff;
		if (diff > 0.0) {
			average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
		}

		sidechain_shares_found = m_totalFoundSidechainShares;
		sidechain_shares_failed = m_totalFailedSidechainShares;
		total_stratum_shares = m_totalStratumShares;
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	char shares_failed_buf[64] = {};
	if (sidechain_shares_failed) {
		log::Stream s(shares_failed_buf);
		s << log::Yellow() << "\nP2Pool shares failed = " << sidechain_shares_failed << log::NoColor();
	}

	LOGINFO(0, "status" <<
		"\nHashrate (15m est)   = " << log::Hashrate(hashrate_15m) <<
		"\nHashrate (1h  est)   = " << log::Hashrate(hashrate_1h) <<
		"\nHashrate (24h est)   = " << log::Hashrate(hashrate_24h) <<
		"\nStratum hashes       = " << total_hashes <<
		"\nStratum shares       = " << total_stratum_shares <<
		"\nP2Pool shares found  = " << sidechain_shares_found << static_cast<const char*>(shares_failed_buf) <<
		"\nAverage effort       = " << average_effort << '%' <<
		"\nCurrent effort       = " << static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double() << '%' <<
		"\nConnections          = " << m_numConnections.load() << " (" << m_numIncomingConnections.load() << " incoming)"
	);
}

// Compresses 64-bit hashes value into 16-bit value (5 bits for shift, 11 bits for data)
enum HashValue : uint64_t {
	bits = 11,
	mask = (1 << bits) - 1,
};

static constexpr FORCEINLINE uint64_t hash_uncompress(uint64_t h)
{
	return (h & HashValue::mask) << (h >> HashValue::bits);
};

enum HashMaxValue : uint64_t {
	value = hash_uncompress(std::numeric_limits<uint16_t>::max())
};

static FORCEINLINE uint16_t hash_compress(uint64_t h)
{
	if (h <= HashValue::mask) {
		return static_cast<uint16_t>(h);
	}

	if (h >= HashMaxValue::value) {
		return std::numeric_limits<uint16_t>::max();
	}

	const uint64_t shift = bsr(h) - (HashValue::bits - 1);
	return static_cast<uint16_t>((shift << HashValue::bits) | (h >> shift));
}

void StratumServer::update_auto_diff(StratumClient* client, const uint64_t timestamp, const uint64_t hashes)
{
	const uint16_t hashes_compressed = hash_compress(hashes);
	client->m_autoDiffWindowHashes += hash_uncompress(hashes_compressed);

	const uint32_t k = client->m_autoDiffIndex++;
	constexpr uint32_t N = StratumClient::AUTO_DIFF_SIZE;

	StratumClient::AutoDiffData& auto_diff_data = client->m_autoDiffData[k % N];

	if (k >= N) {
		client->m_autoDiffWindowHashes -= hash_uncompress(auto_diff_data.m_hashes);
	}

	const uint16_t t1 = auto_diff_data.m_timestamp;
	const uint16_t t2 = static_cast<uint16_t>(timestamp);
	auto_diff_data.m_timestamp = t2;
	auto_diff_data.m_hashes = hashes_compressed;

	if (k >= N) {
		// Full window
		const uint16_t dt = t2 - t1;
		client->m_autoDiff.lo = std::max<uint64_t>((client->m_autoDiffWindowHashes * AUTO_DIFF_TARGET_TIME) / (dt ? dt : 1), MIN_DIFF);
		client->m_autoDiff.hi = 0;
	}
	else if (k >= 10) {
		// Partial window
		const uint64_t h0 = hash_uncompress(client->m_autoDiffData[0].m_hashes);
		const uint16_t dt = client->m_autoDiffData[k].m_timestamp - client->m_autoDiffData[0].m_timestamp;

		client->m_autoDiff.lo = std::max<uint64_t>(((client->m_autoDiffWindowHashes - h0) * AUTO_DIFF_TARGET_TIME) / (dt ? dt : 1), MIN_DIFF);
		client->m_autoDiff.hi = 0;
	}
	else if (k == 0) {
		// First share, fix auto diff to current difficulty until we have at least 10 shares
		client->m_autoDiff.lo = hashes;
		client->m_autoDiff.hi = 0;
	}
}

void StratumServer::on_blobs_ready()
{
	check_event_loop_thread(__func__);

	std::vector<BlobsData*> blobs_queue;
	blobs_queue.reserve(2);

	{
		MutexLock lock(m_blobsQueueLock);
		blobs_queue = m_blobsQueue;
		m_blobsQueue.clear();
	}

	if (blobs_queue.empty()) {
		return;
	}

	ON_SCOPE_LEAVE([&blobs_queue]()
		{
			for (BlobsData* data : blobs_queue) {
				delete data;
			}
		});

	// Legacy pre-generated blobs from on_block are unused now — each client below
	// derives its own blob from its per-miner-wallet template. The BlobsData queue
	// is still drained (and freed by ON_SCOPE_LEAVE) purely as an async wake-up.

	size_t numClientsProcessed = 0;
	uint32_t num_sent = 0;

	const uint64_t cur_time = seconds_since_epoch();

	for (StratumClient* client = static_cast<StratumClient*>(m_connectedClientsList->m_prev); client != m_connectedClientsList; client = static_cast<StratumClient*>(client->m_prev)) {
		++numClientsProcessed;

		if (!client->m_rpcId) {
			// Not logged in yet, on_login() will send the job to this client. Also close inactive connections.
			if (cur_time >= client->m_connectedTime + 10) {
				LOGWARN(4, "client " << static_cast<char*>(client->m_addrString) << " didn't send login data");
				client->ban(m_banTime);
				client->close();
			}
			continue;
		}

		// Find the right BlockTemplate for this client's wallet
		BlockTemplate* tpl = template_for(client->m_minerWallet);
		if (!tpl) {
			tpl = &m_pool->block_template();
		}

		const uint32_t extra_nonce = m_extraNonce.fetch_add(1);

		uint8_t hashing_blob[128];
		uint64_t height, sidechain_height;
		difficulty_type difficulty, aux_diff, sidechain_difficulty;
		hash seed_hash;
		size_t nonce_offset;
		uint32_t template_id;

		const size_t blob_size = tpl->get_hashing_blob(extra_nonce, hashing_blob, height, sidechain_height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset, template_id);

		uint64_t target = std::max(difficulty.target(), sidechain_difficulty.target());
		target = std::max(target, aux_diff.target());

		if (client->m_customDiff.lo) {
			target = std::max(target, client->m_customDiff.target());
		}
		else if (m_autoDiff) {
			// Limit autodiff to 4000000 for maximum compatibility
			target = std::max(target, TARGET_4_BYTES_LIMIT);

			if (client->m_autoDiff.lo) {
				const uint32_t k = client->m_autoDiffIndex;
				const uint16_t elapsed_time = static_cast<uint16_t>(cur_time) - client->m_autoDiffData[(k - 1) % StratumClient::AUTO_DIFF_SIZE].m_timestamp;
				if (elapsed_time > AUTO_DIFF_TARGET_TIME * 5) {
					// More than 500% effort, reduce the auto diff by 1/8 every time until the share is found
					client->m_autoDiff.lo = std::max<uint64_t>(client->m_autoDiff.lo - client->m_autoDiff.lo / 8, MIN_DIFF);
				}
				target = std::max(target, client->m_autoDiff.target());
			}
			else {
				// Not enough shares from the client yet, start with 500k diff and cut diff in half every 16 seconds
				target = std::max(target, AUTODIFF_START);

				const uint64_t num_halvings = (cur_time - client->m_connectedTime) / 16;
				constexpr uint64_t max_target = (std::numeric_limits<uint64_t>::max() / MIN_DIFF) + 1;
				for (uint64_t i = 0; (i < num_halvings) && (target < max_target); ++i) {
					target *= 2;
				}
				target = std::min<uint64_t>(target, max_target);
			}
		}

		uint32_t job_id;
		{
			job_id = ++client->m_perConnectionJobId;

			StratumClient::SavedJob& saved_job = client->m_jobs[job_id % StratumClient::JOBS_SIZE];
			saved_job.job_id = job_id;
			saved_job.extra_nonce = extra_nonce;
			saved_job.template_id = template_id;
			saved_job.target = target;
		}
		client->m_lastJobTarget = target;

		const bool result = send(client,
			[target, &hashing_blob, blob_size, job_id, height, &seed_hash](uint8_t* buf, size_t buf_size)
			{
				log::hex_buf target_hex(&target);

				if (target >= TARGET_4_BYTES_LIMIT) {
					target_hex.m_data += sizeof(uint32_t);
					target_hex.m_size -= sizeof(uint32_t);
				}

				log::Stream s(buf, buf_size);
				s << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{\"blob\":\"";
				s << log::hex_buf(hashing_blob, blob_size) << "\",\"job_id\":\"";
				s << log::Hex(job_id) << "\",\"target\":\"";
				s << target_hex << "\",\"algo\":\"rx/0\",\"height\":";
				s << height << ",\"seed_hash\":\"";
				s << seed_hash << "\"}}\n";
				return s.m_pos;
			});

		if (result) {
			++num_sent;
		}
		else {
			client->close();
		}
	}

	const uint32_t num_connections = m_numConnections;
	if (numClientsProcessed != num_connections) {
		LOGWARN(1, "client list is broken, expected " << num_connections << ", got " << numClientsProcessed << " clients");
	}

	LOGINFO(3, "sent new job to " << num_sent << '/' << numClientsProcessed << " clients");
}

void StratumServer::update_hashrate_data(uint64_t hashes, uint64_t timestamp)
{
	constexpr size_t N = array_size(&StratumServer::m_hashrateData);

	WriteLock lock(m_hashrateDataLock);

	if (hashes) {
		m_cumulativeHashes += hashes;
		++m_totalStratumShares;

		// P2Pool-nano warning
#ifndef P2POOL_LOG_DISABLE
		// Check the hashrate when enough shares is found
		if (((m_totalStratumShares & 63) == 0) && m_pool->side_chain().is_nano()) {
			const HashrateData& head = m_hashrateData[m_hashrateDataHead];
			const HashrateData& tail = m_hashrateData[m_hashrateDataTail_24h];

			const int64_t dt = static_cast<int64_t>(head.m_timestamp - tail.m_timestamp);

			if (dt > 0) {
				const uint64_t total_hashes = head.m_cumulativeHashes - tail.m_cumulativeHashes;
				const uint64_t hashrate = total_hashes / dt;

				if (hashrate > 30000) {
					LOGINFO(0, log::LightRed() << "Your hashrate is " << log::Hashrate(hashrate) << ". Please switch from P2Pool-nano to P2Pool-mini or P2Pool-main. P2Pool-nano is recommended only for small-scale miners.");
				}
			}
		}
#endif // P2POOL_LOG_DISABLE
	}

	HashrateData* data = m_hashrateData;
	HashrateData& head = data[m_hashrateDataHead];
	if (head.m_timestamp == timestamp) {
		head.m_cumulativeHashes = m_cumulativeHashes;
	}
	else {
		m_hashrateDataHead = (m_hashrateDataHead + 1) % N;
		data[m_hashrateDataHead] = { timestamp, m_cumulativeHashes };
	}

	while (data[m_hashrateDataTail_15m].m_timestamp + 15ul * 60ul < timestamp) {
		m_hashrateDataTail_15m = (m_hashrateDataTail_15m + 1) % N;
	}

	while (data[m_hashrateDataTail_1h].m_timestamp + 60ul * 60ul < timestamp) {
		m_hashrateDataTail_1h = (m_hashrateDataTail_1h + 1) % N;
	}

	while (data[m_hashrateDataTail_24h].m_timestamp + 60ul * 60ul * 24ul < timestamp) {
		m_hashrateDataTail_24h = (m_hashrateDataTail_24h + 1) % N;
	}
}

void StratumServer::on_share_found(uv_work_t* req)
{
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);
	StratumServer* server = share->m_server;

	if (share->m_allocated) {
		BACKGROUND_JOB_START(StratumServer::on_share_found);
	}

	if (server->is_banned(share->m_clientIPv6, share->m_clientAddr)) {
		share->m_highEnoughDifficulty = false;
		share->m_result = SubmittedShare::Result::BANNED;
		return;
	}

	p2pool* pool = server->m_pool;

	const uint64_t target = share->m_target;
	const uint64_t hashes = share->m_hashes;

	if (share->m_highEnoughDifficulty || server->m_enableFullValidation) {
		if (pool->stopped()) {
			LOGWARN(0, "p2pool is shutting down, but a share was found. Trying to process it anyway!");
		}

		uint8_t blob[128];
		uint64_t height;
		difficulty_type difficulty;
		difficulty_type aux_diff;
		difficulty_type sidechain_difficulty;
		hash seed_hash;
		size_t nonce_offset;

		const uint32_t blob_size = share->m_tpl->get_hashing_blob(share->m_templateId, share->m_extraNonce, blob, height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset);
		if (!blob_size) {
			LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " got a stale share");
			share->m_result = SubmittedShare::Result::STALE;
			return;
		}

		for (uint32_t i = 0, nonce = share->m_nonce; i < sizeof(share->m_nonce); ++i) {
			blob[nonce_offset + i] = nonce & 255;
			nonce >>= 8;
		}

		hash pow_hash;
		if (!pool->calculate_hash(blob, blob_size, height, seed_hash, pow_hash, false)) {
			LOGWARN(3, "client " << static_cast<char*>(share->m_clientAddrString) << " couldn't check share PoW");
			share->m_result = SubmittedShare::Result::COULDNT_CHECK_POW;
			return;
		}

		if (pow_hash != share->m_resultHash) {
			LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " submitted a share with invalid PoW");
			share->m_result = SubmittedShare::Result::INVALID_POW;
			share->m_score = BAD_SHARE_POINTS;

			// Calculate the same hash second time to check if it's an unstable hardware that caused this
			hash pow_hash2;
			if (pool->calculate_hash(blob, blob_size, height, seed_hash, pow_hash2, true) && (pow_hash2 != pow_hash)) {
				LOGERR(0, "UNSTABLE HARDWARE DETECTED: Calculated the same hash twice, got different results: " << pow_hash << " != " << pow_hash2);
			}

			return;
		}

		share->m_score = GOOD_SHARE_POINTS;

		if (share->m_highEnoughDifficulty) {
			const double diff = sidechain_difficulty.to_double();
			time_t prev_time;
			const time_t cur_time = time(nullptr);
			{
				WriteLock lock(server->m_hashrateDataLock);

				const uint64_t n = server->m_cumulativeHashes + hashes;
				share->m_effort = static_cast<double>(n - server->m_cumulativeHashesAtLastShare) * 100.0 / diff;
				server->m_cumulativeHashesAtLastShare = n;

				server->m_cumulativeFoundSharesDiff += diff;
				++server->m_totalFoundSidechainShares;

				prev_time = server->m_lastSidechainShareFoundTime;
				server->m_lastSidechainShareFoundTime = cur_time;
			}

			if (!share->m_tpl->submit_sidechain_block(share->m_templateId, share->m_nonce, share->m_extraNonce)) {
				WriteLock lock(server->m_hashrateDataLock);

				if (server->m_totalFoundSidechainShares > 0) {
					--server->m_totalFoundSidechainShares;
					++server->m_totalFailedSidechainShares;
					server->m_lastSidechainShareFoundTime = prev_time;
				}
			}
		}
	}

	// Send the response to miner
	const uint64_t value = share->m_resultHash.u64()[HASH_SIZE / sizeof(uint64_t) - 1];

	if (LIKELY(value < target)) {
		const uint64_t timestamp = share->m_timestamp;
		server->update_hashrate_data(hashes, timestamp);
		server->api_update_local_stats(timestamp);
		share->m_result = SubmittedShare::Result::OK;
	}
	else {
		LOGWARN(4, "client " << static_cast<char*>(share->m_clientAddrString) << " got a low diff share");
		share->m_result = SubmittedShare::Result::LOW_DIFF;
		share->m_score = BAD_SHARE_POINTS;
	}
}

void StratumServer::on_after_share_found(uv_work_t* req, int /*status*/)
{
	SubmittedShare* share = reinterpret_cast<SubmittedShare*>(req->data);
	StratumServer* server = share->m_server;

	server->check_event_loop_thread(__func__);

	bool share_found = false;

	const char* s = share->m_clientCustomUser;
	const char* w = share->m_clientWallet;

	if (share->m_highEnoughDifficulty) {
		if (share->m_result == SubmittedShare::Result::OK) {
			LOGINFO(0, log::Green() << "SHARE FOUND: mainchain height " << share->m_mainchainHeight << ", sidechain height " << share->m_sidechainHeight << ", diff " << share->m_sidechainDifficulty << ", client " << static_cast<char*>(share->m_clientAddrString) << (*s ? ", user " : "") << s << ", wallet " << w << ", effort " << share->m_effort << '%');
			share_found = true;
		}
		else {
			static const char* reason_list[] = {
				"stale share",
				"couldn't check PoW",
				"low difficulty",
				"invalid PoW",
				"worker banned",
			};
			static_assert(array_size(reason_list) == static_cast<size_t>(SubmittedShare::Result::OK), "Update reason_list to match SubmittedShare::Result enum");

			const size_t k = static_cast<size_t>(share->m_result);
			const char* reason = (k < array_size(reason_list)) ? reason_list[k] : "unknown";
			LOGWARN(0, "INVALID SHARE: mainchain height " << share->m_mainchainHeight << ", sidechain height " << share->m_sidechainHeight << ", diff " << share->m_sidechainDifficulty << ", client " << static_cast<char*>(share->m_clientAddrString) << (*s ? ", user " : "") << s << ", wallet " << w << ", reason: " << reason);
		}
	}
	else if (share->m_result == SubmittedShare::Result::OK) {
		// Per-miner-wallet share accounting: log every accepted stratum share at level 3
		// (on by default) so the operator can audit which wallet each share pays into.
		// Tune down with log_level 2 if this is too chatty.
		LOGINFO(3, "share accepted: client " << log::Gray() << static_cast<char*>(share->m_clientAddrString) << log::NoColor()
			<< (*s ? ", user " : "") << s
			<< ", wallet " << log::Green() << w << log::NoColor()
			<< ", hashes " << share->m_hashes);
	}

	// Update wallet stats for all accepted shares
	if (share->m_result == SubmittedShare::Result::OK) {
		server->update_wallet_stats(share);
	}

	const bool bad_share = (share->m_result == SubmittedShare::Result::LOW_DIFF) || (share->m_result == SubmittedShare::Result::INVALID_POW);

	StratumClient* client = share->m_client;

	if (client->m_resetCounter.load() == share->m_clientResetCounter) {
		const bool result = server->send(client,
			[share](uint8_t* buf, size_t buf_size)
			{
				log::Stream s(buf, buf_size);
				switch (share->m_result) {
				case SubmittedShare::Result::STALE:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n";
					break;
				case SubmittedShare::Result::COULDNT_CHECK_POW:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Couldn't check PoW\"}}\n";
					break;
				case SubmittedShare::Result::LOW_DIFF:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Low diff share\"}}\n";
					break;
				case SubmittedShare::Result::INVALID_POW:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Invalid PoW\"}}\n";
					break;
				case SubmittedShare::Result::BANNED:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Banned\"}}\n";
					break;
				case SubmittedShare::Result::OK:
					s << "{\"id\":" << share->m_id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n";
					break;
				}
				return s.m_pos;
			});

		client->m_score = std::min(client->m_score + share->m_score, MAX_SCORE);

		if (share_found) {
			++client->m_sidechainShares;
		}

		if (bad_share && (client->m_score <= BAN_THRESHOLD_POINTS)) {
			client->ban(server->m_banTime);
			client->close();
		}
		else if (!result) {
			client->close();
		}
	}
	else if (bad_share) {
		server->ban(share->m_clientIPv6, share->m_clientAddr, server->m_banTime);
	}

	if (share->m_allocated) {
		auto it = std::find(server->m_pendingShareChecks.begin(), server->m_pendingShareChecks.end(), share);
		if (it != server->m_pendingShareChecks.end()) {
			server->m_pendingShareChecks.erase(it);
		}

		delete share;

		if (!server->m_pendingShareChecks.empty()) {
			SubmittedShare* share2 = server->m_pendingShareChecks.front();

			const int err = uv_queue_work(&server->m_loop, &share2->m_req, on_share_found, on_after_share_found);
			if (err) {
				LOGERR(1, "uv_queue_work failed, error " << uv_err_name(err));

				// If uv_queue_work failed, process this share here anyway
				server->on_share_found(&share2->m_req);
				server->on_after_share_found(&share2->m_req, 0);
			}
		}

		LOGINFO(5, "on_after_share_found: pending share checks count = " << server->m_pendingShareChecks.size());

		BACKGROUND_JOB_STOP(StratumServer::on_share_found);
	}
}

void StratumServer::on_shutdown()
{
	{
		MutexLock lock(m_resetShareCountersLock);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_resetShareCountersAsync), nullptr);
	}
	{
		MutexLock lock(m_blobsQueueLock);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_blobsAsync), nullptr);
	}
	{
		MutexLock lock(m_showWorkersLock);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_showWorkersAsync), nullptr);
	}
}

StratumServer::StratumClient::StratumClient()
	: Client(m_rawReadBuf, sizeof(m_rawReadBuf))
	, m_stratumReadBufBytes(0)
	, m_rpcId(0)
	, m_perConnectionJobId(0)
	, m_connectedTime(0)
	, m_jobs{}
	, m_autoDiffData{}
	, m_autoDiffWindowHashes(0)
	, m_autoDiffIndex(0)
	, m_customDiff{}
	, m_autoDiff{}
	, m_customUser{}
	, m_minerWallet(nullptr)
	, m_lastJobTarget(0)
	, m_score(0)
	, m_stratumShares(0)
	, m_sidechainShares(0)
{
	m_rawReadBuf[0] = '\0';
	m_stratumReadBuf[0] = '\0';
}

void StratumServer::StratumClient::reset()
{
	Client::reset();

	m_stratumReadBuf[0] = '\0';
	m_stratumReadBufBytes = 0;

	m_rpcId = 0;
	m_perConnectionJobId = 0;
	m_connectedTime = 0;

	for (int i = 0; i < JOBS_SIZE; ++i) {
		m_jobs[i].job_id = 0;
	}

	m_autoDiffWindowHashes = 0;
	m_autoDiffIndex = 0;
	m_customDiff = {};
	m_autoDiff = {};
	m_customUser[0] = '\0';
	m_minerWallet = Wallet(nullptr);

	m_lastJobTarget = 0;

	m_score = 0;

	m_stratumShares = 0;
	m_sidechainShares = 0;
}

bool StratumServer::StratumClient::on_connect()
{
	m_connectedTime = seconds_since_epoch();
	return true;
}

bool StratumServer::StratumClient::on_read(const char* data, uint32_t size)
{
#ifdef WITH_TLS
	if (!m_tlsChecked) {
		if (data[0] == 0x16) {
			if (!m_tls.init()) {
				LOGWARN(5, "client " << static_cast<const char*>(m_addrString) << ": TLS init failed");
				return false;
			}
			LOGINFO(5, "client " << log::Gray() << static_cast<const char*>(m_addrString) << log::NoColor() << " is using TLS");
		}
		m_tlsChecked = true;
	}
#endif

	auto on_parse = [this](const char* data, uint32_t size) {
		if (static_cast<size_t>(m_stratumReadBufBytes) + size > STRATUM_BUF_SIZE) {
			LOGWARN(4, "client " << static_cast<const char*>(m_addrString) << " sent too long Stratum message");
			ban(static_cast<StratumServer*>(m_owner)->m_banTime);
			return false;
		}

		memcpy(m_stratumReadBuf + m_stratumReadBufBytes, data, size);
		m_stratumReadBufBytes += size;

		char* line_start = m_stratumReadBuf;
		const char* e = line_start + m_stratumReadBufBytes;
		for (char *c = line_start + m_stratumReadBufBytes - size; c < e; ++c) {
			if (*c == '\n') {
				// Check if the line starts with "GET " or "HEAD" (an HTTP request)
				if (static_cast<StratumServer*>(m_owner)->http_enabled() && (c - line_start >= 4)) {
					const uint32_t line_start_data = read_unaligned(reinterpret_cast<uint32_t*>(line_start));

					const bool is_http_get  = (line_start_data == 0x20544547U);
					const bool is_http_head = (line_start_data == 0x44414548U);

					if (is_http_get || is_http_head) {
						LOGINFO(5, "client " << log::Gray() << static_cast<const char*>(m_addrString) << log::NoColor() << " sent an HTTP " << (is_http_get ? "GET" : "HEAD") << " request");

						// Parse URL path
						char* url_start = line_start + 4; // Skip "GET "
						char* url_end = url_start;
						while (url_end < c && *url_end != ' ' && *url_end != '?') {
							++url_end;
						}

						send_http_response(is_http_get, url_start, url_end);
						close();
						return true;
					}
				}

				*c = '\0';
				if (!process_request(line_start, static_cast<uint32_t>(c - line_start))) {
					ban(static_cast<StratumServer*>(m_owner)->m_banTime);
					return false;
				}

				line_start = c + 1;
			}
		}

		// Move the possible unfinished line to the beginning of m_stratumReadBuf to free up more space for reading
		if (line_start != m_stratumReadBuf) {
			m_stratumReadBufBytes = static_cast<uint32_t>(m_stratumReadBuf + m_stratumReadBufBytes - line_start);
			if (m_stratumReadBufBytes > 0) {
				memmove(m_stratumReadBuf, line_start, m_stratumReadBufBytes);
			}
		}

		return true;
	};

#ifdef WITH_TLS
	if (!m_tls.is_empty()) {
		auto on_write = [this](const uint8_t* data, size_t size) {
			return m_owner->send(this, [data, size](uint8_t* buf, size_t buf_size) -> size_t {
				if (buf_size < size) {
					return 0;
				}
				memcpy(buf, data, size);
				return size;
			}, true);
		};

		return m_tls.on_read(data, size, std::move(on_parse), std::move(on_write));
	}
#endif

	return on_parse(data, size);
}

bool StratumServer::StratumClient::process_request(char* data, uint32_t size)
{
	rapidjson::Document doc;
	if (doc.Parse(data, size).HasParseError()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (parse error)");
		return false;
	}

	if (!doc.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (not an object)");
		return false;
	}

	const auto id_it = doc.FindMember("id");
	if (id_it == doc.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('id' field not found)");
		return false;
	}

	const auto& id = id_it->value;
	if (!id.IsUint()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('id' field is not an integer)");
		return false;
	}

	const auto method_it = doc.FindMember("method");
	if (method_it == doc.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('method' field not found)");
		return false;
	}

	const auto& method = method_it->value;
	if (!method.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request ('method' field is not a string)");
		return false;
	}

	const char* s = method.GetString();
	if (strcmp(s, "login") == 0) {
		LOGINFO(6, "incoming login from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_login(doc, id.GetUint());
	}
	if (strcmp(s, "submit") == 0) {
		LOGINFO(6, "incoming share from " << log::Gray() << static_cast<char*>(m_addrString));
		return process_submit(doc, id.GetUint());
	}
	if (strcmp(s, "keepalived") == 0) {
		LOGINFO(6, "incoming keepalive from " << log::Gray() << static_cast<char*>(m_addrString));
		return true;
	}

	LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON request (unknown method)");
	return false;
}

template<typename T>
bool StratumServer::StratumClient::process_login(T& doc, uint32_t id)
{
	const auto params_it = doc.FindMember("params");
	if (params_it == doc.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON login request ('params' field not found)");
		return false;
	}

	const auto& params = params_it->value;
	if (!params.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON login request ('params' field is not an object)");
		return false;
	}

	const auto login_it = params.FindMember("login");
	if (login_it == params.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid login params ('login' field not found)");
		return false;
	}

	const auto& login = login_it->value;
	if (!login.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid login params ('login' field is not a string)");
		return false;
	}

	return static_cast<StratumServer*>(m_owner)->on_login(this, id, login.GetString());
}

template<typename T>
bool StratumServer::StratumClient::process_submit(T& doc, uint32_t id)
{
	const auto params_it = doc.FindMember("params");
	if (params_it == doc.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON submit request ('params' field not found)");
		return false;
	}

	const auto& params = params_it->value;
	if (!params.IsObject()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid JSON submit request ('params' field is not an object)");
		return false;
	}

	const auto rpcId_it = params.FindMember("id");
	if (rpcId_it == params.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('id' field not found)");
		return false;
	}

	const auto& rpcId = rpcId_it->value;
	if (!rpcId.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('id' field is not a string)");
		return false;
	}

	const auto job_id_it = params.FindMember("job_id");
	if (job_id_it == params.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('job_id' field not found)");
		return false;
	}

	const auto& job_id = job_id_it->value;
	if (!job_id.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('job_id' field is not a string)");
		return false;
	}

	const auto nonce_it = params.FindMember("nonce");
	if (nonce_it == params.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field not found)");
		return false;
	}

	const auto& nonce = nonce_it->value;
	if (!nonce.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field is not a string)");
		return false;
	}

	if (nonce.GetStringLength() != sizeof(uint32_t) * 2) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('nonce' field has invalid length)");
		return false;
	}

	const auto result_it = params.FindMember("result");
	if (result_it == params.MemberEnd()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field not found)");
		return false;
	}

	const auto& result = result_it->value;
	if (!result.IsString()) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field is not a string)");
		return false;
	}

	if (result.GetStringLength() != HASH_SIZE * 2) {
		LOGWARN(4, "client " << static_cast<char*>(m_addrString) << " invalid submit params ('result' field has invalid length)");
		return false;
	}

	return static_cast<StratumServer*>(m_owner)->on_submit(this, id, job_id.GetString(), nonce.GetString(), result.GetString());
}

bool StratumServer::StratumClient::send_http_response(bool send_content, char* url_start, char* url_end)
{
	StratumServer* server = static_cast<StratumServer*>(m_owner);

	// Check if this is a /wallet_stats request
	const size_t url_len = url_end - url_start;
	if (url_len >= 13 && memcmp(url_start, "/wallet_stats", 13) == 0) {
		// Extract wallet parameter if present
		char* query_start = url_end;
		while (*query_start != ' ' && *query_start != '\0' && *query_start != '\r' && *query_start != '\n') {
			if (*query_start == '?') {
				++query_start;
				break;
			}
			++query_start;
		}

		const char* wallet_filter = nullptr;
		char wallet_buf[Wallet::ADDRESS_LENGTH + 1] = {};

		// Parse ?wallet= parameter
		if (*query_start != ' ' && *query_start != '\0') {
			const char* wallet_param = strstr(query_start, "wallet=");
			if (wallet_param) {
				wallet_param += 7; // Skip "wallet="
				size_t i = 0;
				while (i < Wallet::ADDRESS_LENGTH && wallet_param[i] != ' ' && wallet_param[i] != '&' && wallet_param[i] != '\0' && wallet_param[i] != '\r' && wallet_param[i] != '\n') {
					wallet_buf[i] = wallet_param[i];
					++i;
				}
				wallet_buf[i] = '\0';
				wallet_filter = wallet_buf;
			}
		}

		std::string json = server->build_wallet_stats_json(wallet_filter);

		return m_owner->send(this, [send_content, json = std::move(json)](uint8_t *buf, size_t buf_size) -> size_t {
			log::Stream s(buf, buf_size);
			s << "HTTP/1.1 200 OK\r\n"
			  << "Content-Length: " << json.size() << "\r\n"
			  << "Content-Type: application/json\r\n"
			  << "Connection: Closed\r\n\r\n";

			if (send_content) {
				s << json;
			}

			return s.m_pos;
		});
	}

	// Default response
	return m_owner->send(this, [send_content](uint8_t *buf, size_t buf_size) -> size_t {
		static constexpr uint8_t data[] =
			"HTTP/1.1 200 OK\r\n"
			"Content-Length: 21\r\n"
			"Content-Type: text/plain\r\n"
			"Connection: Closed\r\n\r\n"
			"P2Pool Stratum online";

		const size_t data_size = send_content ? (sizeof(data) - 1) : (sizeof(data) - 1 - 21);

		if (buf_size < data_size) {
			return 0;
		}

		memcpy(buf, data, data_size);
		return data_size;
	});
}

void StratumServer::api_update_local_stats(uint64_t timestamp)
{
	if (!m_pool->api() || !m_pool->params().m_localStats || m_pool->stopped()) {
		return;
	}

	// Rate limit to no more than once in 20 seconds.
	uint64_t t = m_apiLastUpdateTime.load();
	if (timestamp < t + 20) {
		return;
	}

	if (!m_apiLastUpdateTime.compare_exchange_strong(t, timestamp)) {
		return;
	}

	uint64_t hashes_15m, hashes_1h, hashes_24h, total_hashes;
	int64_t dt_15m, dt_1h, dt_24h;

	uint64_t hashes_since_last_share;
	double average_effort;
	uint32_t shares_found, shares_failed;
	time_t last_share_found_time;
	uint64_t total_stratum_shares;

	{
		ReadLock lock(m_hashrateDataLock);

		total_hashes = m_cumulativeHashes;
		hashes_since_last_share = m_cumulativeHashes - m_cumulativeHashesAtLastShare;

		const HashrateData* data = m_hashrateData;
		const HashrateData& head = data[m_hashrateDataHead];
		const HashrateData& tail_15m = data[m_hashrateDataTail_15m];
		const HashrateData& tail_1h = data[m_hashrateDataTail_1h];
		const HashrateData& tail_24h = data[m_hashrateDataTail_24h];

		hashes_15m = head.m_cumulativeHashes - tail_15m.m_cumulativeHashes;
		dt_15m = static_cast<int64_t>(head.m_timestamp - tail_15m.m_timestamp);

		hashes_1h = head.m_cumulativeHashes - tail_1h.m_cumulativeHashes;
		dt_1h = static_cast<int64_t>(head.m_timestamp - tail_1h.m_timestamp);

		hashes_24h = head.m_cumulativeHashes - tail_24h.m_cumulativeHashes;
		dt_24h = static_cast<int64_t>(head.m_timestamp - tail_24h.m_timestamp);

		average_effort = 0.0;
		const double diff = m_cumulativeFoundSharesDiff;
		if (diff > 0.0) {
			average_effort = static_cast<double>(m_cumulativeHashesAtLastShare) * 100.0 / diff;
		}

		shares_found = m_totalFoundSidechainShares;
		shares_failed = m_totalFailedSidechainShares;
		last_share_found_time = m_lastSidechainShareFoundTime;
		total_stratum_shares = m_totalStratumShares;
	}

	const uint64_t hashrate_15m = (dt_15m > 0) ? (hashes_15m / dt_15m) : 0;
	const uint64_t hashrate_1h  = (dt_1h  > 0) ? (hashes_1h  / dt_1h ) : 0;
	const uint64_t hashrate_24h = (dt_24h > 0) ? (hashes_24h / dt_24h) : 0;

	double current_effort = static_cast<double>(hashes_since_last_share) * 100.0 / m_pool->side_chain().difficulty().to_double();

	uint32_t connections = m_numConnections;
	uint32_t incoming_connections = m_numIncomingConnections;

	const double block_reward_share_percent = m_pool->side_chain().get_reward_share(m_pool->params().m_miningWallet) * 100.0;

	CallOnLoop(&m_loop, [=]() {
		m_pool->api()->set(p2pool_api::Category::LOCAL, "stratum", [=](log::Stream& s) {
			s	<< "{\"hashrate_15m\":" << hashrate_15m
				<< ",\"hashrate_1h\":" << hashrate_1h
				<< ",\"hashrate_24h\":" << hashrate_24h
				<< ",\"total_hashes\":" << total_hashes
				<< ",\"total_stratum_shares\":" << total_stratum_shares
				<< ",\"last_share_found_time\":" << last_share_found_time
				<< ",\"shares_found\":" << shares_found
				<< ",\"shares_failed\":" << shares_failed
				<< ",\"average_effort\":" << average_effort
				<< ",\"current_effort\":" << current_effort
				<< ",\"connections\":" << connections
				<< ",\"incoming_connections\":" << incoming_connections
				<< ",\"block_reward_share_percent\":" << block_reward_share_percent
				<< ",\"wallet\":\"" << m_pool->params().m_displayWallet << '"'
				<< ",\"workers\":[";

			const difficulty_type pool_diff = m_pool->side_chain().difficulty();
			bool first = true;

			for (const StratumClient* client = static_cast<StratumClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<StratumClient*>(client->m_next)) {
				if (!first) {
					s << ',';
				}
				difficulty_type diff = pool_diff;
				if (client->m_lastJobTarget > 1) {
					uint64_t r;
					diff.lo = udiv128(1, 0, client->m_lastJobTarget, &r);
					diff.hi = 0;
					if (r) {
						++diff.lo;
					}
				}

				s 	<< '"' << static_cast<const char*>(client->m_addrString) << ','
					<< (timestamp - client->m_connectedTime) << ','
					<< diff << ','
					<< (client->m_autoDiff.lo / AUTO_DIFF_TARGET_TIME) << ','
					<< (client->m_rpcId ? client->m_customUser : "not logged in")
					<< '"';

				first = false;
			}

			s	<< "]}";
		});
	});
}

void StratumServer::update_wallet_stats(const SubmittedShare* share)
{
	check_event_loop_thread(__func__);

	const uint64_t timestamp = share->m_timestamp;

	// Parse wallet from the client's wallet string
	Wallet wallet(share->m_clientWallet);
	if (!wallet.valid()) {
		return; // Invalid wallet
	}

	const WalletKey key = wallet_key(wallet);

	WriteLock lock(m_walletStatsLock);

	WalletStats& stats = m_walletStats[key];

	// Initialize address on first use
	if (stats.m_address[0] == '\0') {
		memcpy(stats.m_address, share->m_clientWallet, Wallet::ADDRESS_LENGTH);
		stats.m_address[Wallet::ADDRESS_LENGTH] = '\0';
		stats.m_firstSeen = timestamp;
	}

	stats.m_lastActive = timestamp;
	++stats.m_stratumShares;

	// Update cumulative counters
	stats.m_cumulativeHashes += share->m_hashes;
	stats.m_cumulativeSharesDiff += share->m_sidechainDifficulty.lo;
	++stats.m_cumulativeSharesCount;

	// Update ring buffer
	const uint64_t head = stats.m_head;
	WalletHashrateSample& sample = stats.m_ring[head % WalletStats::RING];

	if (sample.m_timestamp == timestamp) {
		// Same second, accumulate
		sample.m_cumulativeHashes += share->m_hashes;
		sample.m_cumulativeSharesDiff += share->m_sidechainDifficulty.lo;
		++sample.m_cumulativeSharesCount;
	} else {
		// New second, advance head
		const uint64_t new_head = head + 1;
		stats.m_head = new_head;
		WalletHashrateSample& new_sample = stats.m_ring[new_head % WalletStats::RING];
		new_sample.m_timestamp = timestamp;
		new_sample.m_cumulativeHashes = stats.m_cumulativeHashes;
		new_sample.m_cumulativeSharesDiff = stats.m_cumulativeSharesDiff;
		new_sample.m_cumulativeSharesCount = stats.m_cumulativeSharesCount;
	}

	// Update tail pointers for time windows
	constexpr uint64_t windows[] = { 5*60, 15*60, 60*60, 6*60*60, 24*60*60 };
	uint64_t* tails[] = { &stats.m_tail_5m, &stats.m_tail_15m, &stats.m_tail_1h, &stats.m_tail_6h, &stats.m_tail_24h };

	for (int i = 0; i < 5; ++i) {
		uint64_t& tail = *tails[i];
		while ((tail < stats.m_head) && (stats.m_ring[tail % WalletStats::RING].m_timestamp + windows[i] < timestamp)) {
			++tail;
		}
	}

	// Update block/share counters
	if (share->m_highEnoughDifficulty) {
		++stats.m_sidechainSharesFound;
		if (share->m_isMainchainBlock) {
			++stats.m_mainchainBlocksFound;
		}
	}
}

std::string StratumServer::build_wallet_stats_json(const char* wallet_filter) const
{
	const uint64_t now = seconds_since_epoch();

	ReadLock lock(m_walletStatsLock);

	char buf[log::Stream::BUF_SIZE];
	log::Stream s(buf, sizeof(buf));

	if (wallet_filter && *wallet_filter) {
		// Single wallet query - need to parse the wallet string to create WalletKey
		Wallet w(wallet_filter);
		if (!w.valid()) {
			s << "{\"error\":\"invalid wallet address\"}";
			return std::string(s.m_buf, s.m_pos);
		}

		const WalletKey key = wallet_key(w);
		auto it = m_walletStats.find(key);
		if (it == m_walletStats.end()) {
			s << "{\"error\":\"wallet not found\"}";
			return std::string(s.m_buf, s.m_pos);
		}

		const WalletStats& stats = it->second;
		s << "{\"wallet\":\"" << wallet_filter << "\",";
		append_wallet_stats_json(s, stats, now);
		s << "}";
	} else {
		// All wallets
		s << "{\"wallets\":[";
		bool first = true;
		for (const auto& kv : m_walletStats) {
			if (!first) s << ",";
			first = false;

			s << "{\"wallet\":\"" << kv.second.m_address << "\",";
			append_wallet_stats_json(s, kv.second, now);
			s << "}";
		}
		s << "]}";
	}

	return std::string(s.m_buf, s.m_pos);
}

void StratumServer::append_wallet_stats_json(log::Stream& s, const WalletStats& stats, uint64_t /* now */) const
{
	// Calculate hashrates for different time windows using cumulative ring buffer
	const uint64_t head = stats.m_head;

	auto calc_hashrate = [&](uint64_t tail_idx, uint64_t /* window_seconds */) -> uint64_t {
		if (head <= tail_idx) return 0;

		const WalletHashrateSample& head_sample = stats.m_ring[head % WalletStats::RING];
		const WalletHashrateSample& tail_sample = stats.m_ring[tail_idx % WalletStats::RING];

		const uint64_t hashes = head_sample.m_cumulativeHashes - tail_sample.m_cumulativeHashes;
		const uint64_t time_diff = head_sample.m_timestamp - tail_sample.m_timestamp;

		return (time_diff > 0) ? (hashes / time_diff) : 0;
	};

	const uint64_t hr_5m = calc_hashrate(stats.m_tail_5m, 5*60);
	const uint64_t hr_15m = calc_hashrate(stats.m_tail_15m, 15*60);
	const uint64_t hr_1h = calc_hashrate(stats.m_tail_1h, 60*60);
	const uint64_t hr_6h = calc_hashrate(stats.m_tail_6h, 6*60*60);
	const uint64_t hr_24h = calc_hashrate(stats.m_tail_24h, 24*60*60);

	s << "\"hashrate_5m\":" << hr_5m
	  << ",\"hashrate_15m\":" << hr_15m
	  << ",\"hashrate_1h\":" << hr_1h
	  << ",\"hashrate_6h\":" << hr_6h
	  << ",\"hashrate_24h\":" << hr_24h
	  << ",\"total_hashes\":" << stats.m_cumulativeHashes
	  << ",\"shares_count\":" << stats.m_cumulativeSharesCount
	  << ",\"mainchain_blocks_found\":" << stats.m_mainchainBlocksFound
	  << ",\"sidechain_shares_found\":" << stats.m_sidechainSharesFound
	  << ",\"first_seen\":" << stats.m_firstSeen
	  << ",\"last_active\":" << stats.m_lastActive;
}

} // namespace p2pool
