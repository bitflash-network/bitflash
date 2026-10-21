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

btfchat
-------
The chat links to the node as its wallet, for paying and being paid:

  ./bitflash-node -managedtor -chatwallet     in one Terminal window
  ./btfchat -managedtor                       in another

btfchat opens its own window; it keeps a separate identity, data
directory and onion address from the node on purpose.

Mining with XMRig instead
-------------------------
Bitflash-Miner-*-macos-arm64 is a separate download: XMRig and Tor, wired
to the pool. See its README.txt.

Verify what you download
------------------------
  shasum -a 256 -c SHA256SUMS
  gpg --verify SHA256SUMS.asc SHA256SUMS
