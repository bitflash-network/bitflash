# Using Everpool

Everpool pools are P2Pool pools recorded on the Bitflash chain: anyone can
create one, nobody can edit, delete or shut one down, and it keeps going when
its creator leaves. They are open on mainnet from release 1.2.36. How they
work, and what was proved before they opened, is in
[pool-registry.md](pool-registry.md) and in the Everpool repository's
PROOFS.md.

You do not need Everpool to mine through P2Pool: the default pool (pool zero)
is what `-p2pool` already mines. Everpool is for a pool with other rules, or
one of your own with a fee of up to 3%.

**Before you mine a pool, check its fingerprint and its fee, never only its
name.** Anyone can create a pool with any name, "bitflash" included. The
fingerprint is the first 8 hex digits of the pool's id; ask for it where the
pool is announced and compare.

Every node on 1.2.36 or newer also guards pools for the network, at idle
priority and within a fixed budget (128 MB of disk, 64 KB/s). Nothing to set.

## In the wallet's window (from 1.2.37)

Click **Everpool** (in the menu bar, or the button beside Backup Wallet):

- the pool list: pool zero first, then every pool on the chain with its name
  and fingerprint (hover for the full id, right-click to copy it), age, fee,
  status (pending with its confirmations, or active), recent blocks, and what
  your node does with it; pools with names alike are flagged;
- pick a pool to see its rules, fee address and recent blocks, and press
  **Mine this pool** (or **Mine pool zero**): Bitflash asks to restart, and
  after the restart it serves that pool's work on the address shown (copy it
  into the Bitflash Miner or XMRig); **Turn P2Pool mining off** undoes it;
- **Create a pool...**: name, your fee and its address, and the share rules
  if you want other than the defaults. The review shows the pool's id and
  fingerprint, the fee, the 1 BTF burn and that a pool can never be edited or
  deleted; nothing is sent until you tick the box and press the burn button.

## On Windows, without the window

`Everpool.cmd`, beside `Bitflash.exe` in the Windows zip, does the same from
a simple menu, for a node run without the window. Double-click it:

| choice | what it does |
|---|---|
| 1. Open Bitflash | opens the wallet so the helper can talk to it (close Bitflash first if it is open) |
| 2. List pools | every pool on the chain: name, fingerprint, fee, status, blocks found lately |
| 3. Show a pool | everything about one pool |
| 4. Mine a pool | chooses the pool; restart Bitflash from the menu, then run the Bitflash Miner with `mine.cmd p2pool` |
| 5. Create a pool | asks the name and your fee, shows a review, and burns 1 BTF only after you type YES |
| 6. Stop P2Pool mining | Bitflash opens as usual again |

The helper starts Bitflash with its JSON-RPC on 127.0.0.1 only, with a random
password kept in your Bitflash data folder (`everpool-rpc.txt`); nothing leaves
your computer. If your wallet is encrypted, unlock it in Bitflash before
creating a pool. `Everpool.cmd -testnet` uses the test network.

## On Linux, or by hand

Start the node with its RPC (see [rpc.md](rpc.md)), then:

```bash
# every pool: name, fingerprint, fee, status
curl -s -u USER:PASS -d '{"id":1,"method":"poollist","params":[]}' http://127.0.0.1:8432/

# one pool
curl -s -u USER:PASS -d '{"id":1,"method":"poolinfo","params":["POOL_ID"]}' http://127.0.0.1:8432/

# review a new pool (sends nothing), then create it (burns 1 BTF)
curl -s -u USER:PASS -d '{"id":1,"method":"poolcreate","params":["everpool",{"name":"my pool","feebps":100,"feeaddress":"YOUR_ADDRESS"}]}' http://127.0.0.1:8432/
curl -s -u USER:PASS -d '{"id":1,"method":"poolcreate","params":["everpool",{"name":"my pool","feebps":100,"feeaddress":"YOUR_ADDRESS"},"send"]}' http://127.0.0.1:8432/
```

`feebps` is the creator's fee in hundredths of a percent (100 is 1%, at most
300); with a fee, give `feeaddress` too, the address it is paid to. A pool is
active 30 confirmations after its burn, about an hour.

To mine one, restart the node with `-p2pool=POOL_ID` and point XMRig or the
Bitflash Miner at it, exactly as for the default pool:

```bash
bitflash-node -nogui -p2pool=POOL_ID
xmrig -a rx/0 -o 127.0.0.1:3333 -u p2pool -p x
```

`-poolcarry=POOL_ID` keeps and relays a pool without mining it, for anyone who
wants to help a pool they care about stay reachable.

## What to expect

- The first blocks of a new pool take as long as its miners' share of the
  network's hash rate says; a small pool pays rarely but exactly.
- Payouts work as in the default pool: every block a pool finds pays every
  miner of its last window of shares, straight from the coinbase, plus the
  creator's fee if it has one.
- A pool nobody mines goes quiet, and comes back with its old window the next
  time someone mines it (its guardians keep the line).
