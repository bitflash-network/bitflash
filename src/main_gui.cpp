// Bitflash entry point -- starts node threads then runs GUI (or headless).

#include "headers_core.h"
#include "nostr.h"
#include "proxy.h"
#include "selftest.h"
#include "btfchatnode.h"
#include "btfchatwallet.h"
#include "btcswap.h"
#include "invoice.h"
#include "tor.h"
#include "treasury.h"
#include "walletcmd.h"
#include "jsonrpc.h"
#include "p2pool_net.h"
#include <thread>          // hardware_concurrency, to sanity-check /genproclimit
#ifndef _WIN32
#include <csignal>
#endif

// BITFLASH_NO_GUI builds the same entry point without ImGui, GLFW or OpenGL,
// so the binary does not need libGL present just to start. See headless.cpp.
#ifndef BITFLASH_NO_GUI
int RunGUI(int argc, char* argv[]);
#endif

// btfchat.exe runs this instead of RunGUI: its own window, nothing but the
// chat. Declared rather than including gui_chat.h so this file stays free of
// ImGui in the headless build.
#ifdef BITFLASH_CHAT_APP
int RunChatGUI(int argc, char* argv[]);
int RunChatTerminal(int argc, char* argv[]);   // chat_terminal.cpp
#endif

// Global definitions (were in ui.cpp, now here)
map<string,string> mapAddressBook;
bool               gPoolServerRunning = false;

static bool arg(int argc, char* argv[], const char* key)
{
    for (int i=1;i<argc;i++) { string s=argv[i]; if(s==key||s.substr(0,s.find('='))==key) return true; }
    return false;
}
static string argval(int argc, char* argv[], const char* key)
{
    for (int i=1;i<argc;i++) {
        string s=argv[i]; size_t eq=s.find('=');
        if(eq!=string::npos && s.substr(0,eq)==key) return s.substr(eq+1);
    }
    return "";
}

static string argval2(int argc, char* argv[], const char* keySlash, const char* keyDash)
{
    string v = argval(argc, argv, keySlash);
    if (!v.empty())
        return v;
    return argval(argc, argv, keyDash);
}

static bool ReadPassphraseArgument(const string& strArg, string& strPassphraseRet, string& strErrorRet)
{
    strPassphraseRet.clear();
    strErrorRet.clear();
    if (strArg.empty())
    {
        AttachTerminal();
        fprintf(stderr, "Enter wallet passphrase: ");
        fflush(stderr);
        char buf[4096];
        if (!fgets(buf, sizeof(buf), stdin))
        {
            strErrorRet = "could not read passphrase from stdin";
            return false;
        }
        strPassphraseRet = buf;
    }
    else if (strArg[0] == '@')
    {
        string strPath = strArg.substr(1);
        FILE* pf = fopen(strPath.c_str(), "rb");
        if (!pf)
        {
            strErrorRet = strprintf("could not read passphrase file %s", strPath.c_str());
            return false;
        }
        char buf[4096];
        if (!fgets(buf, sizeof(buf), pf))
        {
            fclose(pf);
            strErrorRet = strprintf("passphrase file %s is empty", strPath.c_str());
            return false;
        }
        fclose(pf);
        strPassphraseRet = buf;
    }
    else
    {
        strErrorRet = "passphrase literals on the command line are unsafe; use the option without a value to read stdin, or use @FILE";
        return false;
    }

    while (!strPassphraseRet.empty() &&
           (strPassphraseRet[strPassphraseRet.size() - 1] == '\n' ||
            strPassphraseRet[strPassphraseRet.size() - 1] == '\r'))
        strPassphraseRet.resize(strPassphraseRet.size() - 1);
    if (strPassphraseRet.empty())
    {
        strErrorRet = "empty passphrase";
        return false;
    }
    return true;
}

// The real printf, not the one util.h remaps to OutputDebugStringF. Help that
// goes to debug.log is help nobody asked for: `-help` printed a full page into
// the data directory and returned 0 with an empty terminal, which reads as a
// command that does nothing. Same reason walletcmd.cpp undefines it.
#undef printf

static void PrintUsage()
{
#ifdef BITFLASH_CHAT_APP
    // btfchat gets its own page. Printing the miner's would advertise /gen,
    // /operator and the pool options -- every one of which this binary refuses --
    // and help that lists flags the program rejects is worse than no help: it
    // sends the user to try them.
    printf("btfchat -- the Bitflash chat, as its own program\n");
    printf("\n");
    printf("It carries no chain and runs no peer-to-peer node. It reaches the network\n");
    printf("through two doors, both over Tor: the Bitflash nodes, to look an address up\n");
    printf("and to leave messages for people who are offline, and the other person's\n");
    printf("onion service, to talk. No server of anybody's is involved. Its data\n");
    printf("directory, wallet, keys and onion address are its own -- never the miner's.\n");
    printf("\n");
    printf("General:\n");
    printf("  /help, -help, --help, /?\n");
    printf("  /datadir=PATH              (default: %%APPDATA%%\\Bitflash-chat)\n");
    printf("  /chatport=N                (local port Tor forwards the chat service to,\n");
    printf("                              default 8533; it is never reachable directly)\n");
    printf("  /wallet=PATH               (the Bitflash wallet that pays and receives in the chat;\n");
    printf("                              default: the usual Bitflash data directory. Start that\n");
    printf("                              wallet with /chatwallet)\n");
    printf("  /walletport=N              (its RPC port, if not the default 8432 / testnet 18432)\n");
    printf("  /debug\n");
    printf("\n");
    printf("The identity:\n");
    printf("  The chat identity comes from this data directory's recovery phrase plus a\n");
    printf("  session password you type on the unlock screen. A fresh data directory has\n");
    printf("  no phrase, so install one first:\n");
    printf("\n");
    printf("      btfchat -newphrase\n");
    printf("\n");
    printf("  Use a phrase of its own here. The point of a separate program is that this\n");
    printf("  identity does not lead back to the wallet you mine with.\n");
    printf("\n");
    printf("  A wrong session password does not fail: it opens a different, empty\n");
    printf("  identity. The address is shown after unlocking so you can recognise it.\n");
    printf("  There is nothing stored to compare a password against, which is also why\n");
    printf("  it cannot be recovered.\n");
    printf("\n");
    printf("  /newphrase                 (create a recovery phrase in this data directory)\n");
    printf("  /restorephrase=\"...\"       (restore one)\n");
    printf("  /phrasepassword[=@FILE]    (BIP39 passphrase, read from stdin or a file)\n");
    printf("\n");
    printf("Tor (required -- there is no clearnet fallback, by design):\n");
    printf("  /managedtor[=PATH]         (start the bundled Tor and create the chat's\n");
    printf("                              own onion service)\n");
    printf("  /tor[=HOST:PORT]           (use a Tor already running; default 127.0.0.1:9050)\n");
    printf("  /torbridges                (reach Tor where it is blocked, via Snowflake)\n");
    printf("  /torbridge=LINE            (a bridge line of your own)\n");
    printf("  /notorfallback             (do not fall back to bridges on its own)\n");
    printf("\n");
    printf("Mining options are refused here. Mine with bitflash, chat with btfchat.\n");
    return;
#else
    printf("Bitflash command-line options\n");
    printf("\n");
    printf("General:\n");
    printf("  /help, -help, --help, /?\n");
    printf("  /datadir=PATH\n");
    printf("  /debug\n");
    printf("  /gen\n");
    printf("  /nogui or /daemon\n");
    printf("  /selftest=wallet-keypool, wallet-hd, wallet-format, wallet-storage-sanity,\n");
    printf("            db-env-reopen, wallet-sqlite, wallet-sqlite-migration,\n");
    printf("            wallet-crypto, wallet-encrypt, wallet-portability,\n");
    printf("            net-message,\n");
    printf("            consensus-limits, pool-stratum,\n");
    printf("            parse-money, debug-log-buffer, pow-v2, sigpipe, script-eval, rules-v2, net-hardening, multisig, network-params, socks5-proxy,\n");
    // This list had drifted behind the dispatch table in selftest.cpp: several
    // suites that exist were not named here, so nobody could find them without
    // reading the source. Kept in step now; a suite that cannot be discovered is
    // a suite that stops being run.
    printf("            wallet-sqlite-encrypt, wallet-backend-default, wallet-convert,\n");
    printf("            managed-tor, treasury, chat-link, chat-identity, chat-relay,\n");
    printf("            or chat-live (needs Tor and the network; not run by `make tests`)\n");
    printf("\n");
    printf("Mining mode:\n");
    printf("  /p2pool                    (pooled mining with no pool: XMRig points at this node,\n");
    printf("                              blocks pay every miner of the share window; docs/p2pool.md)\n");
    printf("  /p2poolport=N              (default 3333, on 127.0.0.1 only)\n");
    printf("  /p2poolpayto=ADDRESS       (default: a fresh address of this wallet, changed daily)\n");
    printf("  /operator\n");
    printf("  /participant=POOL_BTF_ADDRESS\n");
    printf("  /stratumbridge=POOL_BTF_ADDRESS\n");
    printf("  /stratumbridgeport=N       (default 3333)\n");
    printf("  /stratumbridgebind=IP      (bridge listen address, default 127.0.0.1;\n");
    printf("                              0.0.0.0 to offer a public stratum door)\n");
    printf("  /solomine\n");
    printf("  /genproclimit=N            (mining threads; 0 or absent = every core but one)\n");
    printf("  /nolargepages              (do not ask for 2 MB pages for the RandomX\n");
    printf("                              cache, dataset and scratchpads)\n");
    printf("  /checkblocks=N             (blocks re-verified at startup, default 288, 0 = all)\n");
    printf("  /treasuryshare=PCT         (solo: this percent of every block mined here goes to the\n");
    printf("                              Bitflash treasury in the coinbase; 0-50, default 0)\n");
    printf("\n");
    printf("Pool operator announcement:\n");
    printf("  /poolname=NAME\n");
    printf("  /poolfee=PCT\n");
    printf("  /poolfeeto=treasury        (pay the pool fee to the Bitflash treasury instead of keeping it)\n");
    printf("  /pooldashboard=URL  (alias: /pooldash=URL)\n");
    printf("  /poolstatusfile=PATH       (write pool status JSON for dashboards)\n");
    printf("  /poolroundsfile=PATH       (write public pool round proofs JSON)\n");
    printf("\n");
    printf(".btf (Tor onion services):\n");
    printf("  /connectbtf=PEER_BTF_ADDRESS   (keep an outbound connection to this .btf peer)\n");
    printf("  /onionservice=HOST.onion:PORT  (advertise this node's Tor hidden service)\n");
    printf("\n");
    printf("Network:\n");
    printf("  /testnet                   (isolated test network genesis, datadir, port, and magic)\n");
    printf("  /port=N                    (P2P listen port, default 8433; testnet 18433)\n");
    printf("  /rpcuser=U /rpcpassword=P  (start JSON-RPC on 127.0.0.1 -- both required;\n");
    printf("                              this is what an exchange integrates against)\n");
    printf("  /rpcport=N                 (JSON-RPC port, default 8432; testnet 18432)\n");
    printf("  /chatwallet                (let btfchat on this machine pay and receive with this\n");
    printf("                              wallet: RPC on 127.0.0.1, password in <datadir>/.cookie)\n");
    printf("  /btcchain=main|testnet4|test|signet|regtest  (the Bitcoin chain for BTF<->BTC swaps;\n");
    printf("                              default main, testnet4 on Bitflash testnet)\n");
    printf("  /btcdatadir=DIR /btcrpcport=N /btcwallet=NAME  (where this machine's Bitcoin Core is;\n");
    printf("                              its .cookie is read, or /btcrpcuser=U /btcrpcpassword=P)\n");
    printf("  /btcfeerate=BTC            (per 1000 vbytes, when Core has no fee estimate)\n");
    printf("  /invoicewebhook=URL        (invoices: POST each status change to http://host[:port]/path)\n");
    printf("  /invoicewebhooksecret=S    (sign those POSTs: X-Bitflash-Signature: sha256=HMAC(S, body))\n");
    printf("  /invoicenotify=CMD         (invoices: run CMD on each status change, %%s = invoice id)\n");
    printf("  /invoiceminconf=N          (confirmations for an invoice to be paid; 2 mainnet, 1 testnet)\n");
    printf("  /bindaddr=IP               (listen on this address instead of loopback;\n");
    printf("                              only for a Tor running on another machine --\n");
    printf("                              a reachable plain port exposes this node's onion)\n");
    printf("  /socks=HOST:PORT           (SOCKS5 proxy for Nostr, .btf relay, and onion dials)\n");
    printf("  /tor[=HOST:PORT]           (Tor mode; default SOCKS5 proxy is 127.0.0.1:9050)\n");
    printf("  /managedtor[=PATH]         (start Tor, create a hidden service, advertise its onion)\n");
    printf("  /nomanagedtor              (disable automatic bundled Tor startup)\n");
    printf("  /torbridges                (reach Tor via the bundled Snowflake bridges where Tor is blocked)\n");
    printf("  /torbridge=LINE            (add one obfs4/snowflake/webtunnel/meek bridge line; or put\n");
    printf("                              lines in bridges.txt in the data directory)\n");
    printf("  /torrung=SECS              (time given to each bundled bridge transport before the next; 360)\n");
    printf("  /notorfallback             (do not switch to the bundled bridges on your own when\n");
    printf("                              no peer is reached in four minutes; /torfallback=SECS\n");
    printf("                              changes the wait)\n");
    printf("  /btfseed=ADDRESS:ENCHEX    (extra bootstrap peer, repeatable)\n");
    printf("\n");
    printf("Wallet:\n");
    printf("  /backupwallet=FILE         (write a wallet.dat that opens on its own,\n");
    printf("                              then exit; run it again after new addresses)\n");
    printf("  /dumpwallet=FILE           (export private keys as text -- readable by\n");
    printf("                              anyone, so guard it like cash)\n");
    printf("  /importwallet=FILE         (load keys from such a file back in)\n");
    printf("  /encryptwallet[=@FILE]     (rewrite wallet.dat with encrypted private keys\n");
    printf("                              and encrypted HD seed, then exit)\n");
    printf("  /walletpassphrase[=@FILE]  (unlock an encrypted wallet for one-shot\n");
    printf("                              commands; without @FILE reads stdin)\n");
    printf("  /newaddress                (print the next receiving address, then exit)\n");
    printf("  /sendto=ADDRESS,AMOUNT     (spend from this wallet, then exit -- the\n");
    printf("                              only way to send without the window)\n");
    printf("  /newphrase                 (create a twelve-word recovery phrase for a\n");
    printf("                              wallet that has none, show it once, exit)\n");
    printf("  /restorephrase=\"WORDS\"     (rebuild this wallet from a phrase and scan\n");
    printf("                              the chain for its coins, then exit)\n");
    printf("  /restoredepth=N            (with /restorephrase: derive at least N\n");
    printf("                              addresses before giving up)\n");
    printf("  /phrasepassword[=@FILE]    (with /newphrase or /restorephrase: an\n");
    printf("                              extra word mixed into the seed. The words\n");
    printf("                              alone then rebuild nothing. A wrong one\n");
    printf("                              opens an empty wallet without an error)\n");
    printf("  /showderived=N             (list the first N addresses a phrase\n");
    printf("                              installed in this wallet derives)\n");
    printf("  /recoveryaudit             (show how much spendable balance is\n");
    printf("                              covered by the recovery phrase;\n");
    printf("                              exits 2 when wallet.dat is still needed)\n");
    printf("  /walletstorageaudit        (count wallet.dat record types without\n");
    printf("                              printing wallet values, then exit)\n");
    printf("  /walletstorageauditjson=FILE\n");
    printf("                              (write the same audit as deterministic JSON)\n");
    printf("  /walletstoragecheck        (fail closed on inconsistent or unsafe\n");
    printf("                              wallet.dat storage state)\n");
    printf("  /walletsqliteexport=FILE   (copy raw wallet.dat records into an\n");
    printf("                              SQLite store, then exit)\n");
    printf("  /walletsqliteverify=FILE   (compare wallet.dat with a SQLite export,\n");
    printf("                              printing counts only, then exit)\n");
    printf("  /walletsqliterestore=FILE  (rebuild wallet.dat from a SQLite export in\n");
    printf("                              an empty data directory, then exit)\n");
    printf("  /walletsqliteloadcheck=FILE\n");
    printf("                              (parse a SQLite export like the wallet loader)\n");
    printf("  /walletsqlite=FILE         (stage-load a SQLite wallet export, then exit)\n");
    printf("  /walletbackend=sqlite      (opt-in: run the node on <datadir>/wallet.sqlite\n");
    printf("                              instead of wallet.dat; export one first)\n");
    printf("  /rescan                    (walk the chain for coins this wallet owns\n");
    printf("                              but never recorded, then exit)\n");
    printf("\n");
    printf("Each option also accepts '-' instead of '/'.\n");
#endif
}

#define printf OutputDebugStringF

// A privacy option the operator asked for and did not get is worse than no
// option at all: the node comes up looking protected while doing exactly the
// thing the operator was trying to avoid. Where such a request cannot be
// honoured we stop here instead of falling back.
static void StartupRefuse(const string& strWhat, const string& strFix)
{
    AttachTerminal();
    fprintf(stderr, "\nRefusing to start: %s\n", strWhat.c_str());
    if (!strFix.empty())
        fprintf(stderr, "%s\n", strFix.c_str());
    fflush(stderr);
    exit(1);
}

static bool fJsonRpc = false;

static void ParseStartupArguments(int argc, char* argv[])
{
    if (arg(argc,argv,"/datadir") || arg(argc,argv,"-datadir"))
        strSetDataDir = argval2(argc, argv, "/datadir", "-datadir");

    bool fUseTestNet = arg(argc, argv, "/testnet") || arg(argc, argv, "-testnet");
    SelectChainParams(fUseTestNet);

    if (arg(argc,argv,"/debug") || arg(argc,argv,"-debug"))
        fDebug = true;

    if (arg(argc,argv,"/gen") || arg(argc,argv,"-gen"))
    {
        fGenerateBitcoins = 1;
        // Mining mode defaults to MINE_RELAY, and nothing in this parser ever
        // changed it, so BitcoinMiner() returned immediately at its relay guard
        // and /gen mined nothing at all. /operator and /participant still set
        // their own mode below, so only the unqualified case is affected.
        if (nMineMode == MINE_RELAY)
            nMineMode = MINE_SOLO;
        fMineModeFromCommandLine = true;
    }

    if (arg(argc,argv,"/solomine") || arg(argc,argv,"-solomine"))
        fSoloMineTest = true;

    string strCheckBlocks = argval2(argc, argv, "/checkblocks", "-checkblocks");
    if (!strCheckBlocks.empty())
        nCheckBlocksOnLoad = atoi(strCheckBlocks.c_str());

    // Must be read before LoadBlockIndex(), which is what first calls
    // RandomXInit() and fixes how the cache is allocated.
    if (arg(argc,argv,"/nolargepages") || arg(argc,argv,"-nolargepages"))
        fRandomXLargePages = false;

    // /genproclimit=N -- threads to hash with. 0 or absent means automatic,
    // which is every core but one. Named after Bitcoin's own option so it reads
    // familiarly to anyone who has run one of these before.
    string strProcLimit = argval2(argc, argv, "/genproclimit", "-genproclimit");
    if (!strProcLimit.empty())
    {
        int n = atoi(strProcLimit.c_str());
        unsigned int nCores = std::thread::hardware_concurrency();
        if (n < 0)
            fprintf(stderr, "Ignoring /genproclimit=%s: not a thread count\n",
                    strProcLimit.c_str());
        else if (nCores > 0 && n > (int)nCores * 4)
            // Well past diminishing returns, and every thread still costs a
            // scratchpad. Refuse rather than quietly thrash the machine.
            fprintf(stderr, "Ignoring /genproclimit=%d: this machine has %u core(s)\n",
                    n, nCores);
        else
            nMinerThreads = n;   // 0 stays automatic
    }

    if (arg(argc,argv,"/operator") || arg(argc,argv,"-operator"))
    {
        nMineMode = MINE_OPERATOR;
        fMineModeFromCommandLine = true;
    }

    // P2Pool (docs/p2pool.md): pooled mining with no pool. XMRig points at
    // this node, 127.0.0.1:3333; every block pays the share window directly.
    if (arg(argc,argv,"/p2pool") || arg(argc,argv,"-p2pool"))
    {
        if (nMineMode == MINE_OPERATOR)
            StartupRefuse("-p2pool and -operator do not go together",
                          "P2Pool needs no operator: every miner runs their own node.");
        fP2PoolMode = true;
        string strPort = argval2(argc, argv, "/p2poolport", "-p2poolport");
        if (!strPort.empty())
        {
            long n = atol(strPort.c_str());
            if (n <= 1024 || n > 65535)
                StartupRefuse(strprintf("-p2poolport=%s is not a usable port", strPort.c_str()),
                              "Pick a port between 1025 and 65535, or leave it out for 3333.");
            nP2PoolPort = (unsigned short)n;
        }
        strP2PoolPayTo = argval2(argc, argv, "/p2poolpayto", "-p2poolpayto");
        uint160 h;
        if (!strP2PoolPayTo.empty() && !AddressToHash160(strP2PoolPayTo, h))
            StartupRefuse(strprintf("-p2poolpayto=%s is not a Bitflash address", strP2PoolPayTo.c_str()),
                          "Leave it out to be paid at a fresh address of this wallet, changed every day.");
    }

    if (arg(argc,argv,"/participant") || arg(argc,argv,"-participant"))
    {
        nMineMode = MINE_PARTICIPANT;
        strParticipantPool = argval2(argc, argv, "/participant", "-participant");
        fMineModeFromCommandLine = true;
    }

    if (arg(argc,argv,"/stratumbridge") || arg(argc,argv,"-stratumbridge"))
    {
        fStratumBridge = true;
        string bridgePool = argval2(argc, argv, "/stratumbridge", "-stratumbridge");
        if (!bridgePool.empty())
            strParticipantPool = bridgePool;
    }

    string bridgePort = argval2(argc, argv, "/stratumbridgeport", "-stratumbridgeport");
    if (!bridgePort.empty())
    {
        int nPort = atoi(bridgePort.c_str());
        if (nPort > 0 && nPort <= 65535)
            nStratumBridgePort = nPort;
    }
    string bridgeBind = argval2(argc, argv, "/stratumbridgebind", "-stratumbridgebind");
    if (!bridgeBind.empty())
        strStratumBridgeBind = bridgeBind;

    string poolName = argval2(argc, argv, "/poolname", "-poolname");
    if (!poolName.empty())
        strPoolName = poolName;

    string poolDash = argval2(argc, argv, "/pooldashboard", "-pooldashboard");
    if (poolDash.empty())
        poolDash = argval2(argc, argv, "/pooldash", "-pooldash");
    if (!poolDash.empty())
        strPoolDashboardUrl = poolDash;

    string poolFee = argval2(argc, argv, "/poolfee", "-poolfee");
    if (!poolFee.empty())
        dPoolFeePercent = atof(poolFee.c_str());

    string poolFeeTo = argval2(argc, argv, "/poolfeeto", "-poolfeeto");
    if (!poolFeeTo.empty())
    {
        // This used to `return 1` from a void function: gcc let it through
        // and the node started anyway with the fee going to the default.
        if (poolFeeTo != "treasury" && poolFeeTo != "operator")
            StartupRefuse(strprintf("-poolfeeto is 'treasury' or 'operator', not '%s'", poolFeeTo.c_str()), "");
        fPoolFeeToTreasury = poolFeeTo == "treasury";
    }

    string treasuryShare = argval2(argc, argv, "/treasuryshare", "-treasuryshare");
    if (!treasuryShare.empty())
    {
        int n = atoi(treasuryShare.c_str());
        if (n < 0 || n > treasury::SHARE_MAX_PERCENT)
            StartupRefuse(strprintf("-treasuryshare is 0 to %d percent, not '%s'", treasury::SHARE_MAX_PERCENT,
                                    treasuryShare.c_str()), "");
        nTreasurySharePercent = n;
    }

    string poolStatusFile = argval2(argc, argv, "/poolstatusfile", "-poolstatusfile");
    if (!poolStatusFile.empty())
        strPoolStatusFile = poolStatusFile;

    string poolRoundsFile = argval2(argc, argv, "/poolroundsfile", "-poolroundsfile");
    if (!poolRoundsFile.empty())
        strPoolRoundsFile = poolRoundsFile;

    string btfConnect = argval2(argc, argv, "/connectbtf", "-connectbtf");
    if (!btfConnect.empty())
        strBtfConnect = btfConnect;

    // A testnet bench, cut off from the testnet: -isolate talks to the
    // -connectbtf peer only, and -benchrulesv4=TIME switches rules v4 on at
    // TIME there, so they can be spent and broken with coins before the date.
    // Neither exists on mainnet.
    bool fIsolate = arg(argc, argv, "/isolate") || arg(argc, argv, "-isolate");
    string strBenchV4 = argval2(argc, argv, "/benchrulesv4", "-benchrulesv4");
    if ((fIsolate || !strBenchV4.empty()) && !fUseTestNet)
        StartupRefuse("-isolate and -benchrulesv4 are for a testnet bench only", "add -testnet, or leave them out");
    if (!strBenchV4.empty() && !fIsolate)
        StartupRefuse("-benchrulesv4 without -isolate would fork this node off the public testnet",
                      "add -isolate and -connectbtf=ADDRESS@HOST.onion:PORT of the other bench node");
    if (fIsolate && strBtfConnect.empty())
        StartupRefuse("-isolate needs the bench's other node", "add -connectbtf=ADDRESS@HOST.onion:PORT");
    fBtfIsolated = fIsolate;
    if (!strBenchV4.empty())
    {
        char* end = NULL;
        errno = 0;
        long long n = strtoll(strBenchV4.c_str(), &end, 10);
        if (errno || end == strBenchV4.c_str() || *end != '\0' || n <= 0 || n > 0xffffffffLL)
            StartupRefuse(strprintf("-benchrulesv4=%s is not a unix time", strBenchV4.c_str()), "");
        nBenchRulesV4Time = (unsigned int)n;
        fprintf(stderr, "bench: rules v4 from block time %u on this isolated testnet\n", nBenchRulesV4Time);
    }

    // net.cpp has described nListenPort as "tunable via /port" since it was
    // written, but nothing ever read the option, so the port was fixed at 8433
    // and a second node could not start on a machine already running one. Parse
    // it before Tor setup so a managed hidden service maps the real listener.
    string strPort = argval2(argc, argv, "/port", "-port");
    if (!strPort.empty())
    {
        int nPort = atoi(strPort.c_str());
        if (nPort <= 0 || nPort > 65535)
            fprintf(stderr, "Ignoring /port=%s: not a port number\n", strPort.c_str());
        else
        {
            nListenPort = htons((unsigned short)nPort);
            // Or we would announce a port we never bound.
            addrLocalHost.port = nListenPort;
        }
    }

    // btfchat's port has to be settled BEFORE managed Tor starts: its hidden
    // service is a block in the torrc, which is written once. Asking for the chat
    // later would mean restarting Tor and rotating the onion, so the flag is read
    // here and the port is reserved before anything else happens.
#ifdef BITFLASH_CHAT_APP
    {
        for (int i = 1; i < argc; i++)
        {
            std::string a = argv[i] ? argv[i] : "";
            if (a == "/gen" || a == "-gen" || a == "/operator" || a == "-operator" ||
                a == "/solomine" || a == "-solomine" ||
                a.compare(0, 13, "/participant=") == 0 || a.compare(0, 13, "-participant=") == 0)
                StartupRefuse(strprintf("btfchat does not mine, so %s is refused", a.c_str()),
                              "Mine with bitflash, chat with btfchat. They keep separate data\n"
                              "directories, separate wallets and separate onion addresses on purpose:\n"
                              "a chat identity that leads back to a miner is the thing this split exists\n"
                              "to prevent.");
        }
        string strChatPort = argval2(argc, argv, "/chatport", "-chatport");
        long nChatPort = strChatPort.empty() ? 8533 : atol(strChatPort.c_str());
        if (nChatPort <= 1024 || nChatPort > 65535)
            StartupRefuse(strprintf("/chatport=%s is not a usable port", strChatPort.c_str()),
                          "Pick a port between 1025 and 65535, or leave it out for 8533.");
        btfchat::ChatSetPort((unsigned short)nChatPort);
        fprintf(stderr, "btfchat on 127.0.0.1:%ld, with its own onion service\n", nChatPort);

        // The wallet that pays and receives for this chat: its data directory
        // and RPC port, when they are not the defaults. See btfchatwallet.h.
        string strWalletPort = argval2(argc, argv, "/walletport", "-walletport");
        btfchat::WalletLinkConfigure(argval2(argc, argv, "/wallet", "-wallet"),
                                     strWalletPort.empty() ? 0 : atoi(strWalletPort.c_str()));
    }
#endif

    string onionService = argval2(argc, argv, "/onionservice", "-onionservice");
    if (!onionService.empty())
    {
        string err;
        if (!BtfSetLocalOnionEndpoint(onionService, err))
            fprintf(stderr, "Ignoring /onionservice=%s: %s\n", onionService.c_str(), err.c_str());
        else
            fprintf(stderr, "Direct onion peer endpoint advertised: %s\n",
                    BtfLocalOnionEndpoint().c_str());
    }

    string strBindAddr = argval2(argc, argv, "/bindaddr", "-bindaddr");
    if (!strBindAddr.empty())
        BtfSetListenBindAddress(strBindAddr);

    // -rpcpassword=@FILE reads the secret from a file, the same shape the
    // wallet passphrase options already use, so it never shows up in the
    // process list of a machine other people can log into -- which is what an
    // exchange's box is. A literal still works, because every RPC client ever
    // written expects it to, but it is the form the docs steer away from.
    string strRpcPassword = argval2(argc, argv, "/rpcpassword", "-rpcpassword");
    if (!strRpcPassword.empty() && strRpcPassword[0] == '@')
    {
        // Separate in and out: ReadPassphraseArgument clears its output before
        // it looks at its input, so handing it one string for both empties
        // the "@FILE" and it falls through to reading stdin.
        string strFromFile, strErr;
        if (!ReadPassphraseArgument(strRpcPassword, strFromFile, strErr))
            StartupRefuse("could not read -rpcpassword file: " + strErr, "");
        strRpcPassword = strFromFile;
    }
    // The onion publishes the P2P port and the one above it (the pool's,
    // tor.cpp), each forwarded to the same port on 127.0.0.1. An RPC server
    // bound to either is reachable by anybody over Tor; a bench ran so with
    // -port=18491 -rpcport=18492 before anyone noticed.
    {
        string strRpcPort = argval2(argc, argv, "/rpcport", "-rpcport");
        int nP2P = (int)ntohs(nListenPort);
        int nRpc = atoi(strRpcPort.c_str());
        if (!strRpcPort.empty() && (nRpc == nP2P || nRpc == nP2P + 1))
            StartupRefuse(strprintf("-rpcport=%d is a port this node publishes on its onion", nRpc),
                          strprintf("Ports %d and %d are reachable by anybody over Tor; pick another for the RPC server.",
                                    nP2P, nP2P + 1));
    }
    fJsonRpc = JsonRpcConfigure(argval2(argc, argv, "/rpcuser", "-rpcuser"),
                                strRpcPassword,
                                argval2(argc, argv, "/rpcport", "-rpcport"));
#ifndef BITFLASH_CHAT_APP
    // -chatwallet: let btfchat on this machine pay and receive through this
    // wallet. Off by default -- whatever runs as this user can read the cookie.
    // Given rpcuser/rpcpassword win; the cookie is for when there are none.
    if (!fJsonRpc && (arg(argc, argv, "/chatwallet") || arg(argc, argv, "-chatwallet")))
    {
        fJsonRpc = JsonRpcConfigureCookie(argval2(argc, argv, "/rpcport", "-rpcport"));
        if (fJsonRpc)
            fprintf(stderr, "-chatwallet: btfchat on this machine can use this wallet (cookie in the data directory)\n");
    }
    // The Bitcoin half of a swap: where this machine's Bitcoin Core is. Read
    // only when a btc* call is made; nothing connects to Core before that.
    btcswap::Configure(argval2(argc, argv, "/btcchain", "-btcchain"),
                       argval2(argc, argv, "/btcdatadir", "-btcdatadir"),
                       atoi(argval2(argc, argv, "/btcrpcport", "-btcrpcport").c_str()),
                       argval2(argc, argv, "/btcwallet", "-btcwallet"),
                       argval2(argc, argv, "/btcrpcuser", "-btcrpcuser"),
                       argval2(argc, argv, "/btcrpcpassword", "-btcrpcpassword"),
                       argval2(argc, argv, "/btcfeerate", "-btcfeerate"));
    // Invoices: the shop's own payment gateway (invoice.h).
    {
        invoice::Config ic;
        ic.strWebhookUrl    = argval2(argc, argv, "/invoicewebhook", "-invoicewebhook");
        ic.strWebhookSecret = argval2(argc, argv, "/invoicewebhooksecret", "-invoicewebhooksecret");
        ic.strNotifyCommand = argval2(argc, argv, "/invoicenotify", "-invoicenotify");
        ic.nMinConf         = atoi(argval2(argc, argv, "/invoiceminconf", "-invoiceminconf").c_str());
        std::string strErr;
        if (!invoice::Configure(ic, strErr))
            StartupRefuse(strErr, "");
    }
#endif

    // Commands that do their work and exit have no use for Tor, and starting it
    // for them costs more than the wasted seconds: the child outlives the parent
    // that spawned it, so a selftest or a -newaddress leaves a Tor holding its
    // control port and its data directory, and the next run trips over both.
    // The release packages made this visible -- with tor/ sitting beside the
    // exe, Tor auto-started even for -selftest, which is why the shipped 1.2.20
    // package fails its own managed-tor suite.
    static const char* kShortCommands[] = {
        "selftest", "newaddress", "sendto", "backupwallet", "dumpwallet",
        "importwallet", "encryptwallet", "walletstoragecheck", "walletstorageaudit",
        "newphrase", "restorephrase", "showderived", "recoveryaudit", "rescan",
        "help",
    };
    bool fShortCommand = false;
    for (size_t i = 0; i < ARRAYLEN(kShortCommands); i++)
    {
        string slash = string("/") + kShortCommands[i];
        string dash  = string("-") + kShortCommands[i];
        if (arg(argc, argv, slash.c_str()) || arg(argc, argv, dash.c_str()))
        {
            fShortCommand = true;
            break;
        }
    }

    bool fManagedTor = arg(argc, argv, "/managedtor") || arg(argc, argv, "-managedtor");
    bool fNoManagedTor = arg(argc, argv, "/nomanagedtor") || arg(argc, argv, "-nomanagedtor");
    bool fTorMode = arg(argc, argv, "/tor") || arg(argc, argv, "-tor");
    string socksProxy = argval2(argc, argv, "/socks", "-socks");
    string bundledTorPath;
    bool fAutoManagedTor = !fShortCommand && !fManagedTor && !fNoManagedTor && !fTorMode &&
                            socksProxy.empty() && BtfBundledTorPath(bundledTorPath);
    if (!fShortCommand && (fManagedTor || fAutoManagedTor))
    {
        if (fManagedTor && (fTorMode || !socksProxy.empty()))
            fprintf(stderr, "Warning: /managedtor takes precedence over /tor and /socks\n");

        // Pluggable-transport bridges for reaching Tor where it is blocked,
        // without our rendezvous relays. -torbridges uses the built-in default
        // (Snowflake, no infra needed); -torbridge=<line> adds an obfs4 or
        // snowflake bridge. We resolve a PT binary for each transport present.
        if (arg(argc, argv, "/notorfallback") || arg(argc, argv, "-notorfallback") ||
            BtfTorFallbackDisabledByFile())
            nTorBridgeFallbackSecs = 0;
        string strFallback = argval2(argc, argv, "/torfallback", "-torfallback");
        if (!strFallback.empty())
            nTorBridgeFallbackSecs = atoi(strFallback.c_str());
        string torPath = fManagedTor ? argval2(argc, argv, "/managedtor", "-managedtor") : bundledTorPath;
        BtfSetManagedTorPath(torPath);   // the transports are looked up beside it too
        string strRung = argval2(argc, argv, "/torrung", "-torrung");
        if (!strRung.empty())
            nTorBridgeRungSecs = atoi(strRung.c_str());
        bool fTorBridges = arg(argc, argv, "/torbridges") || arg(argc, argv, "-torbridges");
        string customBridge = argval2(argc, argv, "/torbridge", "-torbridge");
        // The user's own bridges.txt in the data directory counts as asking,
        // the same as -torbridge on the command line.
        std::vector<std::string> userBridges = BtfLoadUserBridges();
        if (fTorBridges || !customBridge.empty() || !userBridges.empty())
        {
            std::vector<std::string> bridges;
            if (fTorBridges)
            {
                std::vector<std::string> def = BtfDefaultBridges();
                bridges.insert(bridges.end(), def.begin(), def.end());
            }
            if (!customBridge.empty())
                bridges.push_back(customBridge);
            bridges.insert(bridges.end(), userBridges.begin(), userBridges.end());

            string strErr;
            if (!BtfConfigureBridges(bridges, (fTorBridges && customBridge.empty() && userBridges.empty())
                                                  ? "snowflake" : "user", strErr))
            {
                // Not a warning. Bridges are asked for by somebody on a
                // network that blocks Tor; carrying on without them means
                // dialling the directory authorities in the clear, which is
                // the observable act they were avoiding.
                StartupRefuse(
                    strprintf("%s, so the bridges you asked for cannot be used", strErr.c_str()),
                    "Install the transport (the release packages ship it under tor/pluggable_transports/),\n"
                    "check the bridge lines (-torbridge, bridges.txt in the data directory), or drop\n"
                    "the bridge options to reach Tor directly -- but only if direct Tor is safe where you are.");
            }
            else
                fprintf(stderr, "Tor bridges enabled (%d bridge%s%s)\n", (int)bridges.size(),
                        bridges.size() == 1 ? "" : "s",
                        userBridges.empty() ? "" : ", bridges.txt read");
        }
        else if (nTorBridgeFallbackSecs > 0)
        {
            // Nothing asked for, but last time only bridges reached the
            // network: start on them, do not spend the four minutes again.
            string last = BtfLastWorkingTransport();
            if (!last.empty() && last != "direct" && last != "user")
            {
                std::vector<BtfBridgeRung> rungs = BtfBundledBridgeRungs();
                for (size_t i = 0; i < rungs.size(); i++)
                    if (rungs[i].name == last)
                    {
                        string strErr;
                        if (BtfConfigureBridges(rungs[i].lines, rungs[i].name, strErr))
                            fprintf(stderr, "Tor: last time only the %s bridges reached the network; starting on them "
                                            "(delete managed-tor/last-working to try direct Tor again)\n", last.c_str());
                        break;
                    }
            }
        }

        string err;
        if (!BtfStartManagedTor(torPath, err))
        {
            // Asked for explicitly: the node has no business coming up without
            // it, because every dial would then leave over the clear network.
            // Picked up automatically: say so and let the other transports try.
            if (fAutoManagedTor)
                fprintf(stderr, "Bundled Tor not enabled automatically: %s\n", err.c_str());
            else
                StartupRefuse(strprintf("managed Tor was requested but did not start: %s", err.c_str()),
                              "Fix the Tor binary path given to -managedtor, or start without it only if\n"
                              "reaching peers over the clear network is acceptable here.");
        }
        else
            fprintf(stderr, "Managed Tor enabled%s: %s\n",
                    fAutoManagedTor ? " automatically" : "",
                    BtfManagedTorStatus().c_str());
    }
    else if (fTorMode)
    {
        if (!socksProxy.empty())
            fprintf(stderr, "Warning: /tor takes precedence over /socks=%s\n",
                    socksProxy.c_str());

        string torProxy = argval2(argc, argv, "/tor", "-tor");
        string err;
        if (!BtfEnableTorProxy(torProxy, err))
            fprintf(stderr, "Ignoring /tor=%s: %s\n", torProxy.c_str(), err.c_str());
        else
            fprintf(stderr, "Tor mode enabled through SOCKS5 proxy %s\n",
                    BtfSocks5ProxyName().c_str());
    }
    else
    {
        if (!socksProxy.empty())
        {
            string err;
            if (!BtfSetSocks5Proxy(socksProxy, err))
                fprintf(stderr, "Ignoring /socks=%s: %s\n", socksProxy.c_str(), err.c_str());
            else
                fprintf(stderr, "SOCKS5 proxy enabled for outbound discovery/relay dials: %s\n",
                        BtfSocks5ProxyName().c_str());
        }
    }

    // /btfseed=ADDRESS:ENCHEX -- extra bootstrap peers, repeatable. Useful for
    // testing the seed path and for private networks that ship no compiled list.
    for (int i = 1; i < argc; i++)
    {
        string s = argv[i];
        size_t eq = s.find('=');
        if (eq == string::npos) continue;
        string key = s.substr(0, eq);
        if (key != "/btfseed" && key != "-btfseed") continue;
        string val = s.substr(eq + 1);
        size_t colon = val.rfind(':');
        if (colon == string::npos || colon + 1 >= val.size())
        {
            fprintf(stderr, "Ignoring %s: expected ADDRESS:ENCHEX\n", s.c_str());
            continue;
        }
        vBtfExtraSeeds.push_back(make_pair(val.substr(0, colon), val.substr(colon + 1)));
    }

}

// Report a startup failure somewhere the user will actually see it.
//
// Every fatal path here wrote to stderr and to printf, and on the platform most
// people use, neither reaches anybody. printf is remapped to OutputDebugStringF,
// so it lands in debug.log inside the data directory. A -mwindows binary
// launched by double-clicking has no stderr at all, and AttachTerminal() cannot
// help: it attaches to a *parent* console, which a double-clicked exe does not
// have.
//
// So the program exited silently. Someone whose wallet.dat needs a newer build
// -- which is exactly what the wallet format guard was added to tell them --
// double-clicked Bitflash and watched nothing happen.
//
// The box is deliberately not shown for a headless node: those run under
// scheduled tasks and services, where a modal dialog waits forever for a click
// nobody is there to make. Headless already has a console when it has one, and
// its output goes to stderr and the log as before.
static void FatalStartupError(bool fHeadless, const string& strWhat, const string& strDetail)
{
    // Managed Tor may already be up: it starts early, and every caller here
    // returns 1 straight afterwards. Without this the Tor we launched outlives
    // the program that owns it, holding a SOCKS port and an onion service for a
    // process that is gone -- and the next start picks new ports and launches
    // another one beside it. Found by hitting a fatal startup error and then
    // finding tor.exe still running with the dead process's torrc on its command
    // line.
    BtfStopManagedTor();

    printf("FATAL: %s\n", strWhat.c_str());
    if (!strDetail.empty())
        printf("FATAL: %s\n", strDetail.c_str());

    AttachTerminal();
    fprintf(stderr, "%s\n", strWhat.c_str());
    if (!strDetail.empty())
        fprintf(stderr, "%s\n", strDetail.c_str());
    fflush(stderr);

#ifdef _WIN32
    if (!fHeadless && GetConsoleWindow() == NULL)
    {
        string strBody = strWhat;
        if (!strDetail.empty())
            strBody += "\n\n" + strDetail;
        strBody += "\n\nNothing was changed. More detail is in debug.log, "
                   "inside the data directory.";
        MessageBoxA(NULL, strBody.c_str(), "Bitflash", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
    }
#else
    (void)fHeadless;
#endif
}

#ifdef _WIN32
// Windows equivalent of the SIGINT/SIGTERM handler the headless loop installs on
// POSIX. Without it a headless node on Windows had no way to reach the clean
// StopNode()+DBFlush() path: Ctrl-C, closing the console window, a service stop
// and OS shutdown all killed it mid-write, and a wallet.dat left unflushed by
// Berkeley DB will not reopen. For CLOSE/LOGOFF/SHUTDOWN the OS terminates us
// shortly after the handler returns, so we set fShutdown and then block until the
// main loop signals the flush is done -- returning any sooner throws the flush
// away, which is the whole bug. (A `taskkill /F` is still an uncatchable hard
// kill; nothing can help there, and nothing should pretend to.)
static volatile bool g_fHeadlessShutdownDone = false;
static BOOL WINAPI HeadlessConsoleCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        fShutdown = true;
        while (!g_fHeadlessShutdownDone)
            Sleep(50);
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

int main(int argc, char* argv[])
{
#ifndef _WIN32
    // See BTF_SEND_FLAGS in compat.h: the signal would end the process on the
    // first write to a peer that has gone, and not every write is a send().
    signal(SIGPIPE, SIG_IGN);
#endif
    if (arg(argc,argv,"/help") || arg(argc,argv,"-help") ||
        arg(argc,argv,"--help") || arg(argc,argv,"/?"))
    {
        // Without this the help prints into nothing. A -mwindows binary starts
        // with no console, so every one of those printfs went nowhere and the
        // one command whose entire job is to tell you something told you
        // nothing at all -- exit code 0, not a byte of output.
        AttachTerminal();
        PrintUsage();
        return 0;
    }

#if defined(BITFLASH_CHAT_APP) && defined(_WIN32)
    // Winsock, for the life of the process.
    //
    // The node gets this from StartNode(), which btfchat does not call -- it has
    // no peer-to-peer node. What was left was the WSAStartup/WSACleanup pair
    // inside PickLocalPort, which exists only to pick Tor's ports and undoes
    // itself immediately. After it, every socket call in the process fails: the
    // chat listener never binds and no outgoing dial connects.
    //
    // It cost an afternoon to see because the failure is quiet. The listener
    // logged "listening on 127.0.0.1:8533" and netstat showed nothing bound,
    // which is the shape of a program that believes it is serving and is not.
    //
    // Never paired with WSACleanup, deliberately: WSAStartup is reference
    // counted, and this reference has to outlive every transient pair that
    // other code makes and unmakes around it.
    {
        WSADATA wsadata;
        int nWsa = WSAStartup(MAKEWORD(2, 2), &wsadata);
        if (nWsa != 0)
        {
            AttachTerminal();
            fprintf(stderr, "btfchat cannot start: the TCP/IP socket library failed "
                            "to start (WSAStartup returned %d)\n", nWsa);
            return 1;
        }
    }
#endif

    ParseStartupArguments(argc, argv);

#ifdef _WIN32
    // Set by the GUI "Restart Now" button: give the previous instance a moment
    // to release the network port and the block-index files before this one
    // opens them, so a relaunch does not race the process it is replacing.
    if (arg(argc, argv, "/restartwait") || arg(argc, argv, "-restartwait"))
        Sleep(2500);
#endif

    // Hidden self-test helper. It must run before LoadWallet(): several
    // storage-sanity scenarios deliberately make wallet.dat unsafe to load.
    string strSelfTestMutateWallet =
        argval2(argc, argv, "/selftestmutatewallet", "-selftestmutatewallet");
    if (!strSelfTestMutateWallet.empty())
        return RunSelfTestMutateWallet(strSelfTestMutateWallet);

    string strSelfTest = argval2(argc, argv, "/selftest", "-selftest");
    if (!strSelfTest.empty())
        return RunSelfTest(strSelfTest);

    // Storage diagnostics must run before LoadWallet(). Their job is to
    // explain wallet.dat states that the normal wallet loader may refuse.
    string strWalletStorageAuditJson =
        argval2(argc, argv, "/walletstorageauditjson", "-walletstorageauditjson");
    bool fDiagWantsAudit = arg(argc,argv,"/walletstorageaudit") ||
                           arg(argc,argv,"-walletstorageaudit") ||
                           !strWalletStorageAuditJson.empty();
    bool fDiagWantsCheck = arg(argc,argv,"/walletstoragecheck") ||
                           arg(argc,argv,"-walletstoragecheck");

    // These diagnostics normally read wallet.dat. Under -walletbackend=sqlite
    // the live wallet is wallet.sqlite, so open it read-only as the active
    // store and let the same scan walk the right file. This runs before the
    // normal backend resolution further down, so validate the value here too.
    string strDiagBackend = argval2(argc, argv, "/walletbackend", "-walletbackend");
    if ((fDiagWantsAudit || fDiagWantsCheck) && !strDiagBackend.empty() &&
        strDiagBackend != "sqlite" && strDiagBackend != "bdb")
    {
        AttachTerminal();
        fprintf(stderr, "Unknown wallet backend '%s'. Use -walletbackend=sqlite "
                        "or -walletbackend=bdb.\n", strDiagBackend.c_str());
        return 1;
    }
    bool fDiagSQLite = (strDiagBackend == "sqlite") &&
                       (fDiagWantsAudit || fDiagWantsCheck);
    if (fDiagSQLite)
    {
        AttachTerminal();
        string strSQLitePath = GetAppDir() + "/wallet.sqlite";
        string strOpenErr;
        if (!WalletSQLiteRuntimeOpenReadOnly(strSQLitePath, strOpenErr))
        {
            fprintf(stderr, "Cannot open the SQLite wallet for diagnostics: %s\n",
                    strOpenErr.c_str());
            return 1;
        }
    }

    if (fDiagWantsAudit)
    {
        int nRet = CmdWalletStorageAudit(strWalletStorageAuditJson);
        if (fDiagSQLite)
            WalletSQLiteRuntimeClose();
        else
            DBFlush(true);
        return nRet;
    }

    if (fDiagWantsCheck)
    {
        int nRet = CmdWalletStorageCheck();
        if (fDiagSQLite)
            WalletSQLiteRuntimeClose();
        else
            DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteExport =
        argval2(argc, argv, "/walletsqliteexport", "-walletsqliteexport");
    if (!strWalletSQLiteExport.empty())
    {
        int nRet = CmdWalletSQLiteExport(strWalletSQLiteExport);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteVerify =
        argval2(argc, argv, "/walletsqliteverify", "-walletsqliteverify");
    if (!strWalletSQLiteVerify.empty())
    {
        int nRet = CmdWalletSQLiteVerify(strWalletSQLiteVerify);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteRestore =
        argval2(argc, argv, "/walletsqliterestore", "-walletsqliterestore");
    if (!strWalletSQLiteRestore.empty())
    {
        int nRet = CmdWalletSQLiteRestore(strWalletSQLiteRestore);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteLoadCheck =
        argval2(argc, argv, "/walletsqliteloadcheck", "-walletsqliteloadcheck");
    if (!strWalletSQLiteLoadCheck.empty())
    {
        int nRet = CmdWalletSQLiteLoadCheck(strWalletSQLiteLoadCheck);
        DBFlush(true);
        return nRet;
    }

    // Berkeley DB reports failure by throwing, and CDB's constructor lets it
    // through. Nothing on this path caught anything, so an unreadable
    // blkindex.dat or wallet.dat -- one written by another platform's Berkeley
    // DB, a truncated file, a version mismatch -- unwound out of main() into
    // std::terminate and abort(). On Windows that surfaces as
    // STATUS_STACK_BUFFER_OVERRUN (0xC0000409) inside ucrtbase.dll: no message,
    // no log line past "Loading wallet...", and a faulting module with nothing
    // to do with the real problem. Confirmed by stack trace:
    //
    //   libdb_cxx-6.2.dll -> CDB::CDB(...) -> LoadBlockIndex(...) -> main()
    //
    // The program knew what had gone wrong and threw the reason away.
    // Needed here, long before the headless branch runs, because whether a
    // startup failure may pop a dialog depends on it.
#ifdef BITFLASH_NO_GUI
    bool fHeadlessStartup = true;
#else
    bool fHeadlessStartup = arg(argc,argv,"/nogui") || arg(argc,argv,"-nogui") ||
                            arg(argc,argv,"/daemon") || arg(argc,argv,"-daemon");
#endif

    string strErrors;
#ifdef BITFLASH_CHAT_APP
    // btfchat carries no chain, and that is a decision, not an omission.
    //
    // Nothing the chat does needs a block: the identity comes from the wallet
    // seed, an address is resolved on the Nostr relays over Tor, and a
    // conversation is a direct onion connection. Loading the index would mean a
    // second copy of the chain on disk, a second sync over Tor, and a chat that
    // cannot say hello until it finishes -- all to show a balance.
    //
    // Staying out of it is also what keeps this process out of the miner's
    // Berkeley DB environment. In this tree blkindex.dat shares an environment
    // with wallet.dat, and that environment is opened with DB_RECOVER, which
    // requires exclusivity: a second process opening it while the first runs
    // rebuilds the regions underneath it. That is how a wallet.dat in this
    // project became unopenable.
    printf("btfchat: no block index -- the chat needs no chain\n");
#else
    printf("Loading block index...\n");
    try
    {
        if (!LoadBlockIndex())
        {
            FatalStartupError(fHeadlessStartup, "Cannot load the block index.", "");
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        FatalStartupError(fHeadlessStartup,
                          strprintf("Cannot read the block index: %s", e.what()),
                          "blkindex.dat and blk0001.dat may be from another machine or "
                          "incomplete. Deleting both is safe -- they are re-downloaded -- "
                          "but never delete wallet.dat, which holds your keys.");
        return 1;
    }
    // The share chain this node kept (p2pool.dat); every node relays shares,
    // so every node keeps it, mining or not.
    P2PoolInit();
#endif

    printf("Loading wallet...\n");
    try
    {
        string strWalletBackend =
            argval2(argc, argv, "/walletbackend", "-walletbackend");
        string strWalletSQLite =
            argval2(argc, argv, "/walletsqlite", "-walletsqlite");

        // A misspelled backend must not fall through to Berkeley DB silently --
        // someone who typed -walletbackend=sqlit meant to run on SQLite, and
        // opening wallet.dat instead of telling them is the wrong surprise.
        if (!strWalletBackend.empty() &&
            strWalletBackend != "sqlite" && strWalletBackend != "bdb")
        {
            AttachTerminal();
            FatalStartupError(fHeadlessStartup,
                strprintf("Unknown wallet backend '%s'.", strWalletBackend.c_str()),
                "Use -walletbackend=sqlite for the SQLite backend, or "
                "-walletbackend=bdb for the Berkeley DB wallet.dat.");
            return 1;
        }

        if (strWalletBackend == "sqlite")
        {
            // Explicit opt-in via the flag. The node runs on
            // <datadir>/wallet.sqlite and never opens wallet.dat, but the user
            // has to have exported one first -- there is no silent migration,
            // and wallet.dat is left
            // exactly where it is so a plain restart goes back to it.
            AttachTerminal();
            string strSQLitePath = GetAppDir() + "/wallet.sqlite";
            if (!FileExists(strSQLitePath.c_str()))
            {
                string strGuide = strprintf(
                    "No SQLite wallet was found at\n"
                    "  %s\n\n"
                    "The SQLite wallet backend is opt-in and needs an exported\n"
                    "wallet first. Your Berkeley DB wallet.dat is not touched by\n"
                    "any of this.\n\n"
                    "  Step 1  Export your existing wallet to SQLite:\n"
                    "            bitflash -walletsqliteexport=\"%s\"\n"
                    "  Step 2  Start again with the SQLite backend:\n"
                    "            bitflash -walletbackend=sqlite\n\n"
                    "To go back to Berkeley DB at any time, just start without\n"
                    "-walletbackend=sqlite. wallet.dat is still your wallet.",
                    strSQLitePath.c_str(), strSQLitePath.c_str());
                FatalStartupError(fHeadlessStartup,
                                  "The SQLite wallet backend needs an exported wallet first.",
                                  strGuide);
                return 1;
            }

            if (!LoadWalletFromSQLiteRuntime(strSQLitePath))
            {
                FatalStartupError(fHeadlessStartup,
                                  "Cannot open the SQLite wallet backend.",
                                  strWalletLoadError);
                return 1;
            }

            fprintf(stderr,
                    "Wallet backend: SQLite\n"
                    "  %s\n"
                    "Your Berkeley DB wallet.dat is left untouched. Restart without\n"
                    "-walletbackend=sqlite to go back to it.\n",
                    strSQLitePath.c_str());
            fflush(stderr);
            // Fall through and run the node normally: every CWalletDB read,
            // write, and erase now routes to this SQLite file.
        }
        else if (!strWalletSQLite.empty())
        {
            AttachTerminal();
            if (!LoadWalletFromSQLite(strWalletSQLite))
            {
                FatalStartupError(fHeadlessStartup,
                                  "Cannot open SQLite wallet export.",
                                  strWalletLoadError);
                return 1;
            }

            fprintf(stderr, "SQLite wallet loaded: read-only staging backend\n");
            fprintf(stderr, "SQLite runtime writes are not enabled yet; exiting before "
                            "network, mining, GUI, or wallet mutation starts.\n");
            fflush(stderr);
            DBFlush(true);
            return 0;
        }
        else if (strWalletBackend == "bdb")
        {
            // Explicit -walletbackend=bdb overrides the marker and the default:
            // force Berkeley DB (LoadWallet creates wallet.dat if none exists).
            if (!LoadWallet())
            {
                FatalStartupError(fHeadlessStartup, "Cannot open wallet.dat.",
                                  strWalletLoadError);
                return 1;
            }
        }
        else
        {
            // No explicit -walletbackend on the command line. Resolve it from
            // the persistent marker, then defaults: an existing wallet.sqlite
            // stays on SQLite, an existing wallet.dat stays on Berkeley DB (the
            // GUI offers to convert), and a fresh install starts on SQLite --
            // the new default. wallet.dat is never touched by any of this.
            string strSQLitePath = GetAppDir() + "/wallet.sqlite";
            bool fSQLiteExists = FileExists(strSQLitePath.c_str());
            bool fWalletDatExists = FileExists((GetAppDir() + "/wallet.dat").c_str());
            string strMarker = ReadWalletBackendMarker();

            bool fUseSQLite = false;
            bool fCreateSQLite = false;
            if (strMarker == "sqlite")
            {
                if (fSQLiteExists)          fUseSQLite = true;
                else if (fWalletDatExists)  fUseSQLite = false;  // marker stale; real wallet is BDB
                else { fUseSQLite = true; fCreateSQLite = true; }
            }
            else if (strMarker == "bdb")
            {
                fUseSQLite = false;
            }
            else  // no marker recorded yet
            {
                if (fSQLiteExists && !fWalletDatExists) fUseSQLite = true;
                else if (fWalletDatExists)              fUseSQLite = false;
                else { fUseSQLite = true; fCreateSQLite = true; }
            }

            if (fUseSQLite)
            {
                AttachTerminal();
                bool fOk = fCreateSQLite
                    ? CreateNewSQLiteWallet(strSQLitePath)
                    : LoadWalletFromSQLiteRuntime(strSQLitePath);
                if (!fOk)
                {
                    FatalStartupError(fHeadlessStartup,
                        fCreateSQLite ? "Cannot create the SQLite wallet."
                                      : "Cannot open the SQLite wallet.",
                        strWalletLoadError);
                    return 1;
                }
                // Record the choice so it is stable from here on.
                if (ReadWalletBackendMarker() != "sqlite")
                    WriteWalletBackendMarker("sqlite");
                fprintf(stderr, "Wallet backend: SQLite\n  %s\n%s",
                        strSQLitePath.c_str(),
                        fCreateSQLite ? "A new wallet was created here.\n" : "");
                fflush(stderr);
                // Fall through and run the node; CWalletDB routes to this file.
            }
            else if (!LoadWallet())
            {
                // LoadWallet() explains itself into strWalletLoadError when it
                // knows why -- an unsupported wallet format, for one, which is
                // the case this whole path exists to make visible.
                FatalStartupError(fHeadlessStartup, "Cannot open wallet.dat.",
                                  strWalletLoadError);
                return 1;
            }
        }

#ifdef BITFLASH_CHAT_APP
        // Skipped, and it has to be: this walks the block index to correct spent
        // flags, and btfchat has no block index. Left in, it opened blkindex.dat
        // in a data directory that has none and threw "Db::open: No such file or
        // directory" -- which the catch below reported as an unreadable
        // wallet.dat, a wallet that was in fact perfectly fine.
        //
        // Nothing is lost by skipping it. There is no chain here to compare the
        // wallet against, and this program never spends: the chat's wallet exists
        // for the seed its identity comes from.
#else
        // After the block index, so there is a chain to compare the wallet
        // against, and before anything reports a balance. Works on either
        // backend: RescanSpentFlags writes corrected flags through CWalletDB,
        // which routes to SQLite when that backend is active.
        RescanSpentFlags();
#endif
    }
    catch (const std::exception& e)
    {
        FatalStartupError(fHeadlessStartup,
                          strprintf("Cannot read wallet.dat: %s", e.what()),
                          "The file was left untouched. A wallet.dat written by a "
                          "different platform's Berkeley DB is the usual cause; back it "
                          "up before trying anything else.");
        return 1;
    }
    printf("Height=%d\n", nBestHeight);

    bool fEncryptWallet = arg(argc, argv, "/encryptwallet") || arg(argc, argv, "-encryptwallet");
    string strEncryptWallet = argval2(argc, argv, "/encryptwallet", "-encryptwallet");
    if (fEncryptWallet)
    {
        string strPassphrase;
        string strPassphraseError;
        if (!ReadPassphraseArgument(strEncryptWallet, strPassphrase, strPassphraseError))
        {
            fprintf(stderr, "Cannot read encryption passphrase: %s\n", strPassphraseError.c_str());
            DBFlush(true);
            return 1;
        }
        int nRet = CmdEncryptWallet(strPassphrase);
        if (nRet != 0)
            DBFlush(true);
        return nRet;
    }

    bool fWalletPassphrase = arg(argc, argv, "/walletpassphrase") || arg(argc, argv, "-walletpassphrase");
    string strWalletPassphrase = argval2(argc, argv, "/walletpassphrase", "-walletpassphrase");
    if (fWalletPassphrase)
    {
        string strPassphrase;
        string strUnlockError;
        if (!ReadPassphraseArgument(strWalletPassphrase, strPassphrase, strUnlockError) ||
            !UnlockWallet(strPassphrase, strUnlockError))
        {
            fprintf(stderr, "Cannot unlock wallet: %s\n", strUnlockError.c_str());
            DBFlush(true);
            return 1;
        }
    }

    // Before the node opens sockets or touches anything: the wallet is loaded,
    // which is all a backup needs, and finishing here means the copy is taken
    // from a quiet directory rather than from under a running node.
    string strBackup = argval2(argc, argv, "/backupwallet", "-backupwallet");
    if (!strBackup.empty())
    {
        bool fOk = BackupWallet(strBackup);
        if (fOk)
        {
            printf("Backed up to %s\n", strBackup.c_str());
            printf("This file opens on its own -- it does not need the database/ "
                   "directory beside it.\n");
            printf("It is a snapshot: coins paid to addresses created after now are "
                   "not in it, so back up again whenever you receive to a new address.\n");
        }
        else
            fprintf(stderr, "Backup failed -- nothing was written.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    string strDump = argval2(argc, argv, "/dumpwallet", "-dumpwallet");
    if (!strDump.empty())
    {
        bool fOk = DumpWallet(strDump);
        if (fOk)
        {
            printf("Wrote %s\n", strDump.c_str());
            printf("It holds your private keys as readable text. Anyone with the file "
                   "can spend these coins -- keep it off shared storage and delete it "
                   "once you have it somewhere safe.\n");
        }
        else
            fprintf(stderr, "Export failed -- nothing was written.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    string strImport = argval2(argc, argv, "/importwallet", "-importwallet");
    if (!strImport.empty())
    {
        int nAdded = 0, nSkipped = 0;
        bool fOk = ImportWallet(strImport, nAdded, nSkipped);
        if (fOk)
        {
            printf("Imported %d key(s); %d were already here.\n", nAdded, nSkipped);
            // Importing a key without looking for its coins leaves the user
            // holding a wallet that says zero about money that is on the
            // chain. That was the old behaviour and it looks exactly like the
            // import having failed.
            if (nAdded > 0)
            {
                string strScanError;
                if (!CanScanWalletTransactions(strScanError))
                {
                    fprintf(stderr, "Cannot scan for imported coins: %s\n",
                            strScanError.c_str());
                    fprintf(stderr, "The key import was written, but the wallet "
                                    "balance was not proven against the chain.\n");
                    DBFlush(true);
                    return 1;
                }
                printf("Looking through the chain for coins belonging to the imported key(s)...\n");
                int nFound = ScanForWalletTransactions(pindexGenesisBlock);
                printf("Found %d transaction(s). Start the node normally to see the balance.\n", nFound);
            }
        }
        else
            fprintf(stderr, "Import failed.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    // /rescan -- walk the chain and pick up anything the wallet's keys own but
    // the wallet never recorded. Cheap to offer and the only recourse when a
    // balance is wrong for this reason.
    string strShow = argval2(argc, argv, "/showderived", "-showderived");
    if (!strShow.empty())
    {
        int nRet = CmdShowDerived(atoi(strShow.c_str()));
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/newaddress") || arg(argc,argv,"-newaddress"))
    {
        int nRet = CmdNewAddress();
        DBFlush(true);
        return nRet;
    }

    // -sendto -- the counterpart to -newaddress. Without it a headless node can
    // be paid and can never pay: SendMoney() has been here since 0.1.0 and only
    // the window ever reached it.
    string strSendTo = argval2(argc, argv, "/sendto", "-sendto");
    if (!strSendTo.empty())
    {
        int nRet = CmdSendTo(strSendTo);
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/recoveryaudit") || arg(argc,argv,"-recoveryaudit"))
    {
        int nRet = CmdRecoveryAudit();
        DBFlush(true);
        return nRet;
    }

    // -phrasepassword is BIP39's extra word for /newphrase and /restorephrase.
    // It is read the same way as the wallet passphrase -- stdin, or @FILE --
    // and for the same reason: a secret typed on the command line survives in
    // the shell history, and this one cannot be changed once coins depend on it.
    bool fWantPhrasePassword = arg(argc, argv, "/phrasepassword") ||
                               arg(argc, argv, "-phrasepassword");
    string strPhrasePassword;
    if (fWantPhrasePassword)
    {
        string strArg = argval2(argc, argv, "/phrasepassword", "-phrasepassword");
        string strErr;
        if (!ReadPassphraseArgument(strArg, strPhrasePassword, strErr))
        {
            AttachTerminal();
            fprintf(stderr, "%s\n", strErr.c_str());
            return 1;
        }
    }

    if (arg(argc,argv,"/newphrase") || arg(argc,argv,"-newphrase"))
    {
        int nRet = CmdNewPhrase(strPhrasePassword);
        DBFlush(true);
        return nRet;
    }

    string strRestore = argval2(argc, argv, "/restorephrase", "-restorephrase");
    if (!strRestore.empty())
    {
        string strDepth = argval2(argc, argv, "/restoredepth", "-restoredepth");
        int nMinDepth = strDepth.empty() ? 0 : atoi(strDepth.c_str());
        int nRet = CmdRestorePhrase(strRestore, strPhrasePassword, nMinDepth);
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/rescan") || arg(argc,argv,"-rescan"))
    {
        string strScanError;
        if (!CanScanWalletTransactions(strScanError))
        {
            fprintf(stderr, "Cannot rescan wallet transactions: %s\n",
                    strScanError.c_str());
            DBFlush(true);
            return 1;
        }
        printf("Rescanning the chain for this wallet's transactions...\n");
        int nFound = ScanForWalletTransactions(pindexGenesisBlock);
        printf("Rescan done: %d transaction(s) added or updated.\n", nFound);
        DBFlush(true);
        return 0;
    }

    if (fGenerateBitcoins && IsWalletLocked())
    {
        fprintf(stderr, "Cannot mine while the encrypted wallet is locked. "
                        "Start with /walletpassphrase or /walletpassphrase=@FILE, or disable mining.\n");
        DBFlush(true);
        return 1;
    }

#ifdef BITFLASH_CHAT_APP
    // No P2P node either: with no chain there is nothing to download, nothing to
    // relay and nothing to announce. btfchat reaches the network through exactly
    // two doors, both over Tor -- the Bitflash nodes' onions, to look an address
    // up and use the mailbox (btfchatnet.h), and the other person's onion, to
    // talk. Fewer doors is the point.
    //
    // ReacceptWalletTransactions is skipped for the same reason: it walks the
    // chain to re-announce our own transactions, and there is no chain to walk.
    printf("btfchat: no peer-to-peer node -- Bitflash nodes over Tor to resolve, onion to talk\n");
#else
    ReacceptWalletTransactions();

    if (!StartNode(strErrors))
    {
        fprintf(stderr,"StartNode: %s\n",strErrors.c_str());
        BtfStopManagedTor();
        return 1;
    }
#endif

    if (nMineMode == MINE_OPERATOR || fP2PoolMode) {
        gPoolServerRunning = true;
        gPoolRunning = true;
        if (_beginthread(ThreadRPCServer, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadRPCServer) failed\n");
    }
    if (fStratumBridge) {
        if (_beginthread(ThreadStratumBridge, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadStratumBridge) failed\n");
    }
    if (fJsonRpc) {
        if (_beginthread(ThreadJsonRpcServer, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadJsonRpcServer) failed\n");
#ifndef BITFLASH_CHAT_APP
        // Invoices are made through the RPC, so they are watched while it runs.
        if (_beginthread(invoice::ThreadInvoices, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadInvoices) failed\n");
#endif
    }
    // An inheritance made over the RPC must still be renewed when the node is
    // later run without it: an owner who stops passing -rpcuser is not dead.
    if (_beginthread(ThreadInheritance, 0, NULL) == (uintptr_t)-1)
        printf("Error: _beginthread(ThreadInheritance) failed\n");
#ifdef BITFLASH_CHAT_APP
    // btfchat never mines. It carries the chain so it validates on its own
    // rather than trusting a server, and it carries a wallet so its address can
    // receive -- but the whole point of a separate binary is that the chat
    // identity does not lead back to a miner, and a chat that mines is a chat
    // that leads back to one.
    fGenerateBitcoins = false;
#else
    if (fGenerateBitcoins)
        StartMinerThreads();
#endif

#ifdef BITFLASH_CHAT_APP
    // btfchat in a terminal: always when built without a window (macOS), and
    // on request elsewhere. A chat has no use for the node's headless loop.
#ifdef BITFLASH_NO_GUI
    bool fChatTerminal = true;
#else
    bool fChatTerminal = arg(argc,argv,"/terminal") || arg(argc,argv,"-terminal") ||
                         arg(argc,argv,"/nogui") || arg(argc,argv,"-nogui");
#endif
    if (fChatTerminal)
    {
        int ret = RunChatTerminal(argc, argv);
        fShutdown = true;
        BtfStopManagedTor();
        DBFlush(true);
        WalletSQLiteRuntimeClose();
        return ret;
    }
#endif

#ifdef BITFLASH_NO_GUI
    // Nothing else this binary can do; /nogui is accepted and redundant.
    bool fHeadless = true;
#else
    bool fHeadless = arg(argc,argv,"/nogui") || arg(argc,argv,"-nogui") ||
                     arg(argc,argv,"/daemon") || arg(argc,argv,"-daemon");
#endif

    if (fHeadless) {
#ifdef _WIN32
        SetConsoleCtrlHandler(HeadlessConsoleCtrlHandler, TRUE);
#else
        auto sig=[](int){fShutdown=true;};
        signal(SIGINT,sig); signal(SIGTERM,sig);
#endif
        printf("Running headless. Ctrl-C to stop.\n");
        while (!fShutdown) Sleep(500);
        StopNode();
        BtfStopManagedTor();
        // Checkpoints, releases wallet.dat from this directory's Berkeley DB
        // environment, and closes it. Declared since 2009 and never once
        // called here, which is why a wallet.dat copied elsewhere would not
        // open -- issue #40. Not optional.
        DBFlush(true);
        // Checkpoint and close the SQLite wallet backend if one is active. A
        // no-op on the Berkeley DB path. Safe to kill before this runs: WAL +
        // synchronous=FULL already made every committed write durable.
        WalletSQLiteRuntimeClose();
#ifdef _WIN32
        // wallet.dat is safely flushed and closed now; let a pending console
        // control handler (CLOSE/LOGOFF/SHUTDOWN) return so the OS can finish.
        g_fHeadlessShutdownDone = true;
#endif
        return 0;
    }

#ifdef BITFLASH_NO_GUI
    return 0;   // unreachable: fHeadless is always true in this build
#elif defined(BITFLASH_CHAT_APP)
    int ret = RunChatGUI(argc, argv);
    fShutdown = true;
    // StopNode() is deliberately not called: there is no node. It waits for
    // node thread slots that never ran, and it calls WSACleanup() -- which would
    // tear down the one Winsock reference this build depends on, while the Tor
    // shutdown below still needs a socket to ask Tor politely to stop.
    BtfStopManagedTor();
    DBFlush(true);
    WalletSQLiteRuntimeClose();
    return ret;
#else
    int ret = RunGUI(argc, argv);
    fShutdown = true;
    StopNode();
    BtfStopManagedTor();
    DBFlush(true);
    WalletSQLiteRuntimeClose();
    return ret;
#endif
}
