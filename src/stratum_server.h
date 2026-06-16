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

#pragma once

#include "tcp_server.h"
#include "wallet.h"
#include <unordered_map>

namespace p2pool {

class p2pool;
class BlockTemplate;
struct MinerData;

static constexpr size_t STRATUM_BUF_SIZE = log::Stream::BUF_SIZE + 1;
static constexpr size_t STRATUM_CALLBACK_BUF_SIZE = 16384;
static constexpr int DEFAULT_STRATUM_PORT = 3333;

class StratumServer : public TCPServer
{
public:
	explicit StratumServer(p2pool *pool);
	~StratumServer() override;

	void on_block(const BlockTemplate& block);

	// True if this wallet is either the pool-operator's fallback wallet
	// or one of the per-miner wallets currently hosted on this node.
	[[nodiscard]] bool is_our_wallet(const Wallet& w) const;

	// Max unique miner wallets we will service in addition to the operator wallet.
	// If exceeded, additional miners fall back to the operator's wallet.
	static constexpr size_t MAX_UNIQUE_MINER_WALLETS = 256;

	struct StratumClient : public Client
	{
		StratumClient();
		FORCEINLINE ~StratumClient() override {}

		static Client* allocate() { return new StratumClient(); }
		virtual size_t get_size() const override { return sizeof(StratumClient); }

		void reset() override;
		[[nodiscard]] bool on_connect() override;
		[[nodiscard]] bool on_read(const char* data, uint32_t size) override;

		[[nodiscard]] bool process_request(char* data, uint32_t size);
		template<typename T> [[nodiscard]] bool process_login(T& doc, uint32_t id);
		template<typename T> [[nodiscard]] bool process_submit(T& doc, uint32_t id);

		bool send_http_response(bool send_content, char* url_start, char* url_end);

		alignas(8) char m_rawReadBuf[STRATUM_BUF_SIZE];

		alignas(8) char m_stratumReadBuf[STRATUM_BUF_SIZE];
		uint32_t m_stratumReadBufBytes;

		uint32_t m_rpcId;
		uint32_t m_perConnectionJobId;
		uint64_t m_connectedTime;

		enum { 
			JOBS_SIZE = 4,
			AUTO_DIFF_SIZE = 64,
			CUSTOM_USER_SIZE = 32,
		};

		struct SavedJob {
			uint32_t job_id;
			uint32_t extra_nonce;
			uint32_t template_id;
			uint64_t target;
		} m_jobs[JOBS_SIZE];

		struct AutoDiffData {
			uint16_t m_timestamp;
			uint16_t m_hashes;
		} m_autoDiffData[AUTO_DIFF_SIZE];

		uint64_t m_autoDiffWindowHashes;
		uint32_t m_autoDiffIndex;

		difficulty_type m_customDiff;
		difficulty_type m_autoDiff;
		char m_customUser[CUSTOM_USER_SIZE];

		// Wallet parsed from stratum login. Invalid = fallback to pool-operator wallet.
		// When valid, this client's shares pay to this wallet via its per-miner BlockTemplate.
		Wallet m_minerWallet{ nullptr };

		uint64_t m_lastJobTarget;

		int32_t m_score;

		uint32_t m_stratumShares;
		uint32_t m_sidechainShares;
	};

	[[nodiscard]] bool on_login(StratumClient* client, uint32_t id, const char* login);
	[[nodiscard]] bool on_submit(StratumClient* client, uint32_t id, const char* job_id_str, const char* nonce_str, const char* result_str);
	[[nodiscard]] uint32_t get_random32();

	void print_status() override;
	void show_workers_async();

	void reset_share_counters();

	bool http_enabled() const;

private:
	[[nodiscard]] const char* get_log_category() const override;

	void print_stratum_status() const;
	void update_auto_diff(StratumClient* client, const uint64_t timestamp, const uint64_t hashes);

	static void on_share_found(uv_work_t* req);
	static void on_after_share_found(uv_work_t* req, int status);

	p2pool* m_pool;
	bool m_autoDiff;
	bool m_enableFullValidation;
	struct BlobsData
	{
		uint32_t m_extraNonceStart = 0;
		std::vector<uint8_t> m_blobs;
		size_t m_blobSize = 0;
		uint64_t m_target = 0;
		uint32_t m_numClientsExpected = 0;
		uint32_t m_templateId = 0;
		uint64_t m_height = 0;
		hash m_seedHash;
	};

	uv_mutex_t m_resetShareCountersLock;
	uv_async_t m_resetShareCountersAsync;

	static void on_reset_share_counters(uv_async_t* handle) { reinterpret_cast<StratumServer*>(handle->data)->on_reset_share_counters(); }
	void on_reset_share_counters();

	uv_mutex_t m_blobsQueueLock;
	uv_async_t m_blobsAsync;
	std::vector<BlobsData*> m_blobsQueue;

	static void on_blobs_ready(uv_async_t* handle) { reinterpret_cast<StratumServer*>(handle->data)->on_blobs_ready(); }
	void on_blobs_ready();

	uv_mutex_t m_showWorkersLock;
	uv_async_t m_showWorkersAsync;

	static void on_show_workers(uv_async_t* handle) { reinterpret_cast<StratumServer*>(handle->data)->show_workers(); }
	void show_workers();

	std::atomic<uint32_t> m_extraNonce;

	// Per-miner-wallet BlockTemplate cache (unique_ptr<BlockTemplate> held alive for
	// the life of this server — never evicted in v1 to keep submit paths simple).
	// Each StratumClient's m_minerWallet maps into this cache; if it exceeds
	// MAX_UNIQUE_MINER_WALLETS new miners fall back to the operator wallet.
	struct WalletKey {
		hash spend;
		hash view;
		FORCEINLINE bool operator==(const WalletKey& o) const { return (spend == o.spend) && (view == o.view); }
	};
	struct WalletKeyHash {
		FORCEINLINE size_t operator()(const WalletKey& k) const noexcept {
			size_t h = 0;
			memcpy(&h, k.spend.h, sizeof(size_t));
			return h;
		}
	};
	struct WalletTemplateEntry {
		BlockTemplate* tpl = nullptr;
		uint32_t ref_count = 0;
	};
	mutable uv_rwlock_t m_walletTemplatesLock;
	std::unordered_map<WalletKey, WalletTemplateEntry, WalletKeyHash> m_walletTemplates;

	static WalletKey wallet_key(const Wallet& w) { return { w.spend_public_key(), w.view_public_key() }; }

public:
	// Get (or lazily create) a BlockTemplate for the given wallet and increment its ref_count.
	// Returns nullptr when the cache is full; caller should fall back to the operator wallet.
	[[nodiscard]] BlockTemplate* acquire_template_for(const Wallet& w);
	// Decrement ref_count for the given wallet. Entry is not removed in v1.
	void release_template_for(const Wallet& w);

	// Look up the BlockTemplate for a wallet without touching ref_count. Returns nullptr if not cached.
	[[nodiscard]] BlockTemplate* template_for(const Wallet& w) const;

	// Fill the full 95-character Monero address for logs (NUL-terminated, so the
	// buffer must be ADDRESS_LENGTH + 1). Empty string when the wallet has not
	// been assigned yet (e.g. pre-login).
	void format_wallet(const Wallet& w, char (&buf)[Wallet::ADDRESS_LENGTH + 1]) const;

private:

	uv_mutex_t m_rngLock;
	std::mt19937_64 m_rng;

	struct SubmittedShare
	{
		uv_work_t m_req = {};
		bool m_allocated = false;

		StratumServer* m_server = nullptr;
		StratumClient* m_client = nullptr;
		// BlockTemplate used to generate the share's job (per-miner-wallet aware).
		// Must remain valid for the lifetime of this submission (we don't evict templates in v1).
		BlockTemplate* m_tpl = nullptr;
		bool m_clientIPv6 = false;
		raw_ip m_clientAddr;
		char m_clientAddrString[Client::ADDR_STRING_SIZE] = {};
		char m_clientCustomUser[StratumClient::CUSTOM_USER_SIZE] = {};
		// Full 95-character Monero wallet address the miner's share pays to (NUL-terminated).
		// Empty when no wallet is attached yet (e.g. pre-login).
		char m_clientWallet[Wallet::ADDRESS_LENGTH + 1] = {};
		uint32_t m_clientResetCounter = 0;
		uint32_t m_rpcId = 0;
		uint32_t m_id = 0;
		uint32_t m_templateId = 0;
		uint32_t m_nonce = 0;
		uint32_t m_extraNonce = 0;
		uint64_t m_target = 0;
		hash m_resultHash;
		difficulty_type m_sidechainDifficulty;
		uint64_t m_mainchainHeight = 0;
		uint64_t m_sidechainHeight = 0;
		double m_effort = 0.0;
		uint64_t m_timestamp = 0;
		uint64_t m_hashes = 0;
		bool m_highEnoughDifficulty = false;
		bool m_isMainchainBlock = false;
		int32_t m_score = 0;

		enum class Result {
			NONE,
			STALE,
			COULDNT_CHECK_POW,
			LOW_DIFF,
			INVALID_POW,
			BANNED,
			OK
		} m_result = Result::NONE;
	};

	struct HashrateData
	{
		uint64_t m_timestamp;
		uint64_t m_cumulativeHashes;
	};

	struct WalletHashrateSample
	{
		uint64_t m_timestamp;
		uint64_t m_cumulativeHashes;
		uint64_t m_cumulativeSharesDiff;
		uint32_t m_cumulativeSharesCount;
		uint32_t m_pad;
	};

	struct WalletStats
	{
		static constexpr size_t RING = 4096;
		char m_address[Wallet::ADDRESS_LENGTH + 1];
		WalletHashrateSample m_ring[RING];
		uint64_t m_head;
		uint64_t m_tail_5m, m_tail_15m, m_tail_1h, m_tail_6h, m_tail_24h;

		uint64_t m_cumulativeHashes;
		uint64_t m_cumulativeSharesDiff;
		uint32_t m_cumulativeSharesCount;

		uint32_t m_mainchainBlocksFound;
		uint32_t m_sidechainSharesFound;
		uint32_t m_sidechainSharesFailed;
		uint32_t m_stratumShares;
		uint64_t m_firstSeen;
		uint64_t m_lastActive;

		WalletStats()
			: m_address{}
			, m_ring{}
			, m_head(0)
			, m_tail_5m(0), m_tail_15m(0), m_tail_1h(0), m_tail_6h(0), m_tail_24h(0)
			, m_cumulativeHashes(0)
			, m_cumulativeSharesDiff(0)
			, m_cumulativeSharesCount(0)
			, m_mainchainBlocksFound(0)
			, m_sidechainSharesFound(0)
			, m_sidechainSharesFailed(0)
			, m_stratumShares(0)
			, m_firstSeen(0)
			, m_lastActive(0)
		{}
	};

	mutable uv_rwlock_t m_walletStatsLock;
	std::unordered_map<WalletKey, WalletStats, WalletKeyHash> m_walletStats;

	mutable uv_rwlock_t m_hashrateDataLock;

	HashrateData m_hashrateData[131072];
	uint64_t m_cumulativeHashes;
	uint64_t m_cumulativeHashesAtLastShare;
	uint64_t m_hashrateDataHead;
	uint64_t m_hashrateDataTail_15m;
	uint64_t m_hashrateDataTail_1h;
	uint64_t m_hashrateDataTail_24h;

	double m_cumulativeFoundSharesDiff;
	uint32_t m_totalFoundSidechainShares;
	uint32_t m_totalFailedSidechainShares;
	time_t m_lastSidechainShareFoundTime;
	uint64_t m_totalStratumShares;

	uint64_t m_banTime;

	std::atomic<uint64_t> m_apiLastUpdateTime;

	std::deque<SubmittedShare*> m_pendingShareChecks;

	void update_hashrate_data(uint64_t hashes, uint64_t timestamp);
	void api_update_local_stats(uint64_t timestamp);

	void update_wallet_stats(const SubmittedShare* share);
	std::string build_wallet_stats_json(const char* wallet_filter) const;
	void append_wallet_stats_json(log::Stream& s, const WalletStats& stats, uint64_t now) const;

	void on_shutdown() override;
};

} // namespace p2pool
