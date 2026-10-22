Bitflash for macOS (Apple silicon: M1 and later)
================================================

Terminal only, no app to install. Everything it needs is in this folder:
the Bitflash node, btfchat, Tor, and the libraries they use.

Once, after unpacking
---------------------
The download is not signed by Apple, so macOS holds it until told it is
wanted. In Terminal, in the folder where you unpacked it:

  xattr -dr com.apple.quarantine Bitflash-*-macos-arm64
  cd Bitflash-*-macos-arm64

The node (wallet and mining)
----------------------------
  ./bitflash-node -managedtor                 run a node, over its own Tor
  ./bitflash-node -managedtor -gen            ... and mine with this Mac
  ./bitflash-node -newaddress                 print an address to receive at

Data lives in ~/.bitflash (btfchat's in ~/.bitflash-chat). Ctrl+C stops it.
The node answers JSON-RPC on 127.0.0.1 (docs/rpc.md).

btfchat (in Terminal, no window)
--------------------------------
Once, to make your chat identity (write the twelve words down, on paper):

  ./btfchat -newphrase

Then, with the node as the chat's wallet (for paying and being paid):

  ./bitflash-node -managedtor -chatwallet     in one Terminal window
  ./btfchat -managedtor                       in another

btfchat asks for a session password (12 characters or more; the same one
every time -- a different password is a different identity), then takes
commands. 'help' lists them all; the everyday ones:

  me                       your address, to give to people
  invite ADDRESS [note]    ask someone to talk
  invites / accept ADDR    answer the ones you got (its first letters are enough)
  chats / open N           your conversations; then just type to send
  ask 1.5 / pay 1.5        ask to be paid / pay what they asked, in BTF
  directory / join N       public communities
  swaps                    BTF-BTC swaps and what each is waiting for
  quit

Messages, invites and posts are printed as they arrive. The chat keeps a
separate identity, data directory and onion address from the node on
purpose.

Mining with XMRig instead
-------------------------
Bitflash-Miner-*-macos-arm64 is a separate download: XMRig and Tor, wired
to the pool. See its README.txt.

Verify what you download
------------------------
  shasum -a 256 -c SHA256SUMS
  gpg --verify SHA256SUMS.asc SHA256SUMS
